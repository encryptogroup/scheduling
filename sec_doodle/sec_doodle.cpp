/**
 \file 		sec_doodle.cpp
 \author	oliver.schick92@gmail.com
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
 Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include <abycore/aby/abyparty.h>
#include <abycore/sharing/sharing.h>

#include "common/sec_doodle.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <iostream>
#include <vector>
#include <iterator>
#include <string>
#include <numeric>
#include <memory>
#include <cstdlib>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

constexpr std::size_t RSA_keylength = 2048;

void parse_selections(
    std::vector<doodle_entry>& result, 
    unsigned char const* selections, 
    std::size_t const message_length
){
    auto parse_base64 = [](unsigned char const c){
        unsigned char result = 255;
        if(c >= 'A' && c <= 'Z'){
            result = c - 'A';
        }
        else if(c >= 'a' && c <= 'z'){
            result = c - 'a' + 26;
        }
        else if(c >= '0' && c <= '9'){
            result = c - '0' + 52;
        }
        else if(c == '+'){
            result = 62;
        }
        else if(c == '/'){
            result = 63;
        }
        return result;
    };
    for(std::size_t i = 0; *selections != '\0' && i < message_length; ++i, ++selections){
        unsigned char b = parse_base64(*selections);
        assert(b != 255);
        result.emplace_back((b >> 4) & 0x3);
        ++i;
        if(i < message_length){
            result.emplace_back((b >> 2) & 0x3);
        }
        ++i;
        if(i < message_length){
            result.emplace_back(b & 0x3);
        }
    }
}


std::string openssl_error(){
    std::string result;
    ERR_print_errors_cb(
        [](const char* err_str, std::size_t len, void* str){
            std::string& s = *static_cast<std::string*>(str);
            s.reserve(s.size() + len);
            s += err_str;
            return 0;
        }, 
        static_cast<void*>(&result)
    );
    return result;
}

struct rsa_data_t{
    RSA* rsa;
    rsa_data_t(char const* const key_file)
    : rsa(nullptr){
        BIO* const pri = BIO_new_file(key_file, "r");
        if(pri == nullptr){
            throw std::runtime_error(std::string("could not open key file:\n") + openssl_error());
        }
        rsa = PEM_read_bio_RSAPrivateKey(pri, nullptr, nullptr, nullptr);
        if(rsa == nullptr){
            throw std::runtime_error(std::string("could not read private key:\n") + openssl_error());
        }
        assert(buffer_size >= static_cast<std::size_t>(RSA_size(rsa)));
        BIO_free(pri);
    }
    ~rsa_data_t(){
        RSA_free(rsa);
    }
    void decrypt_message(
        std::vector<doodle_entry>& result, 
        unsigned char const* const encrypted_message, 
        std::size_t const message_length
    ){
        RSA_private_decrypt(RSA_size(rsa), encrypted_message, msg, rsa, RSA_PKCS1_PADDING);
        parse_selections(result, msg, message_length);
        
    }
    
    static constexpr std::size_t buffer_size = RSA_keylength/8;
    unsigned char msg[buffer_size];
    
};

struct server{
    struct session;
    explicit server(unsigned short const port)
    : socket_(create_socket_(port)) {}
    
    ~server() noexcept{
        if(socket_ >= 0u){
            close(socket_);
        }
    }
    
    server(server const&) = delete;
    
    server& operator=(server const&) = delete;
    
    server(server&& rhs) noexcept
    : socket_(rhs.socket_) {
        rhs.socket_ = -1;
    }
    
    server& operator=(server&& rhs) noexcept{
        if(this == &rhs){
            return *this;
        }
        socket_ = rhs.socket_;
        rhs.socket_ = -1;
        return *this;
    }
    
    session listen() const{
        int const socket = accept(socket_, nullptr, nullptr);
        if(socket < 0){
            throw std::runtime_error("server error: could not connect to client");
        }
        return session(socket);
    }
    
    struct session{
        session(int const socket) noexcept
        : socket_(socket) {}
        
        session(const session&) = delete;
        
        session& operator=(const session&) = delete;
        
        session(session&& rhs) noexcept
        : socket_(rhs.socket_) {
            rhs.socket_ = -1;
        }
        
        session& operator=(session&& rhs) noexcept{
            if(this == &rhs){
                return *this;
            }
            socket_ = rhs.socket_;
            rhs.socket_ = -1;
            return *this;
        }
        
        ~session() noexcept{
            if(socket_ >= 0){
                close(socket_);
            }
        }
        
        int get_socket() const noexcept{
            return socket_;
        }
        
    private:
        int socket_;
    };
    
private:

    static int create_socket_(int const port){
        sockaddr_in addr;
        
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        
        int const s = socket(AF_INET, SOCK_STREAM, 0);
        if(s < 0){
            throw std::runtime_error("server error: could not create socket");
        }
        if(::bind(s, (sockaddr*) &addr, sizeof(addr)) < 0){
            throw std::runtime_error("server error: could not bind socket");
        }
        if(::listen(s, 1) < 0){
            throw std::runtime_error("server error: could not start listening");
        }
        return s;
    }
    
    int socket_;
};

struct ssl_server{
    struct session;
    ssl_server(
        unsigned short const port, 
        char const* const private_key_filename, 
        char const* const certificate_filename
    )
    : s_(port){
        init_openssl_();
        ctx_ = create_context_();
        SSL_CTX_set_ecdh_auto(ctx_, 1);
        if(SSL_CTX_use_certificate_file(ctx_, certificate_filename, SSL_FILETYPE_PEM) <= 0){
            throw std::runtime_error(std::string("could not open certificate file:\n") + openssl_error());
        }
        if(SSL_CTX_use_PrivateKey_file(ctx_, private_key_filename, SSL_FILETYPE_PEM) <= 0){
            throw std::runtime_error(std::string("could not open private key file:\n") + openssl_error());
        }
    }
    
    ~ssl_server() noexcept{
        SSL_CTX_free(ctx_);
        cleanup_openssl_();
    }
    
    session listen() const{
        return session(s_.listen(), ctx_);
    }
    
    struct session{
    public:
        session(server::session&& sess, SSL_CTX* const ctx)
        : session_(std::move(sess)), ssl_(SSL_new(ctx)){
            if(ssl_ == nullptr){
                throw std::runtime_error("could not create ssl:\n" + openssl_error());
            }
            SSL_set_fd(ssl_, session_.get_socket());
            if(SSL_accept(ssl_) <= 0){
                throw std::runtime_error("could not securely connect to client\n" + openssl_error());
            }
        }
        
        session(session&& rhs) noexcept
        : session_(std::move(rhs.session_)), ssl_(rhs.ssl_) {
            rhs.ssl_ = nullptr;
        }
        
        session& operator=(session&& rhs) noexcept{
            if(this == &rhs){
                return *this;
            }
            session_ = std::move(rhs.session_);
            ssl_ = rhs.ssl_;
            rhs.ssl_ = nullptr;
            return *this;
        }
        
        ~session() noexcept{
            SSL_free(ssl_);
        }
        
        std::size_t read(void* const buffer, std::size_t const buffer_size) const noexcept{
            return SSL_read(ssl_, buffer, buffer_size);
        }
        
        std::size_t write(void const* const buffer, std::size_t const buffer_size) noexcept{
            return SSL_write(ssl_, buffer, buffer_size);
        }
        
    private: 
        server::session session_;
        SSL* ssl_;
        
    };
    
private:

    static void init_openssl_() noexcept{
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    }
    
    static void cleanup_openssl_() noexcept{
        EVP_cleanup();
    }
    
    static SSL_CTX* create_context_(){
        SSL_CTX* const ctx = SSL_CTX_new(SSLv23_server_method());
        
        if(ctx == nullptr){
            throw std::runtime_error("could not create SSL context:\n" + openssl_error());
        }
        
        return ctx;
    }
    
    SSL_CTX* ctx_;
    server s_;
};

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
		uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, {
					(void*) nvals, T_NUM, "n",
					"Number of parallel operation elements", false, false }, {
					(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,
					false }, { (void*) secparam, T_NUM, "s",
					"Symmetric Security Bits, default: 128", false, false }, {
					(void*) address, T_STR, "a",
					"IP-address, default: localhost", false, false }, {
					(void*) &int_port, T_NUM, "p", "Port, default: 7766", false,
					false }, { (void*) test_op, T_NUM, "t",
					"Single test (leave out for all operations), default: off",
					false, false } };

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}


	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 64, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
			&port, &test_op);
            
    seclvl sec_lvl = get_sec_lvl(secparam);
    #ifdef TESTING
    test_sec_doodle_circuit(role, (char*) address.c_str(), port, sec_lvl, 1, bitlen, nthreads, mt_alg, S_YAO);
    #else
    char const* const private_key_filename = (role == SERVER ? "../../src/examples/sec_doodle/private-key-1.pem" : "../../src/examples/sec_doodle/private-key-2.pem");
    char const* const certificate_filename = (role == SERVER ? "../../src/examples/sec_doodle/certificate-1.cer" : "../../src/examples/sec_doodle/certificate-2.cer");
    
    rsa_data_t rsa_data(private_key_filename);
    ssl_server s(role == SERVER ? 7779 : 7775, private_key_filename, certificate_filename);
    
    e_sharing sh = S_YAO;
    ABYParty party(role, const_cast<char*>(address.c_str()), port, sec_lvl, bitlen, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party.GetSharings();
    BooleanCircuit* circ = static_cast<BooleanCircuit*>(sharings[sh]->GetCircuitBuildRoutine());
    
    while(true){
        ssl_server::session sess(s.listen());
        constexpr std::size_t buffer_size = RSA_keylength/8;
        unsigned char input[buffer_size];
        sess.read(input, 4);
        
        std::vector<doodle_entry> selections;
        const unsigned int time_slots = input[0] << 24 | input[1] << 16 | input[2] << 8 | input[3];
        unsigned int participants = 0;
        while(sess.read(input, buffer_size) == buffer_size){
            rsa_data.decrypt_message(selections, input, time_slots);
            ++participants;
        }
        for(auto const& sel : selections){
            std::cout << sel << " ";
        }
        std::cout << std::endl;
        doodle_table dt(std::move(selections), participants, time_slots);
        auto const tpl = execute_circuit(party, circ, role, algorithm::yao, dt);
        party.Reset();
        std::size_t const winner = std::get<0>(tpl);
        std::vector<bool> const& nos = std::get<1>(tpl);
        auto send_results = [&](unsigned char* const buf){
            buf[0] = static_cast<unsigned char>(winner >> 24);
            buf[1] = static_cast<unsigned char>(winner >> 16);
            buf[2] = static_cast<unsigned char>(winner >> 8);
            buf[3] = static_cast<unsigned char>(winner);
        
            auto it = nos.begin();
            std::size_t buf_size = 4;
            while(it != nos.end()){
                auto const i = buf_size;
                ++buf_size;
                buf[i] = *it << 7;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it << 6;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it << 5;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it << 4;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it << 3;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it << 2;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it << 1;
                ++it;
                if(it == nos.end()) break;
                buf[i] |= *it;
                ++it;
            }
            std::cout << "data sent: " << sess.write(buf, buf_size) << std::endl;
        };
        
        if(buffer_size > (4 + nos.size()/8)){
            send_results(input);
        }
        else{
            auto buf = std::make_unique<unsigned char[]>(4 + nos.size()/8);
            send_results(buf.get());
        }
        
        std::cout << std::get<0>(tpl) << std::endl;
        for(bool b : std::get<1>(tpl)){
            std::cout << std::boolalpha << b << ", ";
        }
        std::cout << std::endl;
        
    }
    #endif
	return 0;
}

