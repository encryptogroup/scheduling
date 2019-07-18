var tls = require('tls');
var https = require('https');
var http = require('http');
var express = require('express');
var bodyParser = require('body-parser');
var fs = require('fs');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var net = require('net');
var app = express();

var pollNumber = parseInt(fs.readFileSync('pollNumber.txt', 'utf8'));
var pubkeyServer1 = JSON.parse(fs.readFileSync('pubkey-server1-hex.json', 'utf8'));
var pubkeyServer2 = JSON.parse(fs.readFileSync('pubkey-server2-hex.json', 'utf8'));
var server1Port = 7779;
var server1Address = 'localhost';
var server2Port = 7775;
var server2Address = 'localhost';
const POLL_RUNNING = 0;
const POLL_WAITING_RESULT = 1;
const POLL_ENDED = 2;
const passwordLength = 40;

var monthNames = [
    'January',
    'February',
    'March',
    'April',
    'May',
    'June',
    'July',
    'August',
    'September',
    'October',
    'November',
    'December'
];

var dayNames = [
    'Sunday',
    'Monday',
    'Tuesday',
    'Wednesday',
    'Thursday',
    'Friday',
    'Saturday'
];


app.use(bodyParser.urlencoded({
    extended:true
}));
app.use(bodyParser.json());
app.use(express.static('public'));

var socket1;
var socket2;

function shuffle(arr){
    var buf = crypto.randomBytes(arr.length*4);
    for(var i = 0; i < arr.length; ++i){
        var r = (buf[4*i] << 24) |
                (buf[4*i+1] << 16) |
                (buf[4*i+2] << 8) |
                buf[4*i+3];
        r = r & ((1 << 31) - 1);
        var tmp = arr[i];
        arr[i] = arr[i + r % (arr.length - i)];
        arr[i + r % (arr.length - i)] = tmp;
    }
    return arr;
}

function getRandomPermutation(){
    return {
        permutation: [],
        permute: function(arr){
            var i = 0;
	    if(arr.length != this.permutation.length){
		console.log("error this should be equal to permutation.length");
		return arr;
	    }
            for(; i < arr.length; ++i){
		if(i < this.permutation[i]){
                    var tmp = arr[i];
                    arr[i] = arr[this.permutation[i]];
                    arr[this.permutation[i]] = tmp;
		}
            }
            return arr;
        },
        initPermute: function(l){
            this.permutation = new Array(l);
            var i = 0;
            for(; i < this.permutation.length; ++i){
                this.permutation[i] = i;
            }
            this.permutation = shuffle(this.permutation);
	    return this;
        },
        invPermute: function(arr){
            return this.permute(arr);
        }
    };
}

function sendPollInputs(pollPath){
    var content = JSON.parse(fs.readFileSync(pollPath, 'utf8'));
    var p = getRandomPermutation().initPermute(content.maskedData.length);
    function expandToFit(hexstr, num_bytes){
        return '0'.repeat(2*num_bytes - hexstr.length) + hexstr;
    }
    function dataToString(data){ 
	    return expandToFit(content.data.match(/;/g).length.toString(16), 4) + data.toString().replace(/[,\s]/g, '');
    }
    function toRawData(s){
        function hexToInt(charcode){
            if(charcode >= '0'.charCodeAt(0) && charcode <= '9'.charCodeAt(0)){
                return charcode - '0'.charCodeAt(0);
            }
            else if(charcode >= 'A'.charCodeAt(0) && charcode <= 'F'.charCodeAt(0)){
                return charcode - 'A'.charCodeAt(0) + 10;
            }
            else if(charcode >= 'a'.charCodeAt(0) && charcode <= 'f'.charCodeAt(0)){
                return charcode - 'a'.charCodeAt(0) + 10;
            }
        }
        var result = '';
        var i = 0;
        //s is always divisible by 2
        for(; i < s.length; i += 2){
            result += String.fromCharCode((hexToInt(s.charCodeAt(i)) << 4) + hexToInt(s.charCodeAt(i+1)));
        }
        return result;
    }
    function shuffleAccordingShuffledParticipants(arr){
        for(var i = 0; i < arr.length; ++i){
            //only swap if not swapping with self (shuffledParticipants[i] == i)
            //or already swapped the value (shuffledParticipants[i] < i)
            if(content.shuffledParticipants[i] > i){
                var tmp = arr[i];
                arr[i] = arr[content.shuffledParticipants[i]];
                arr[content.shuffledParticipants[i]] = arr[i];
            }
        }
    }
    function writeData(choice){
	console.log("1. " + p.permutation);
        var socket = tls.connect(
            {
                port : choice == 'SERVER1' ? server1Port : server2Port, 
                host : choice == 'SERVER1' ? server1Address : server2Address,
		        ca : fs.readFileSync(choice == 'SERVER1' ? 'server-1-cert.cer' : 'server-2-cert.cer')
            },
            function(){
                var str = dataToString(
                            choice == 'SERVER1' ? 
                            p.permute(content.maskedData) : 
                            p.permute(content.randomData)
                          );
                str = toRawData(str);
		console.log( (choice == 'SERVER1' ? 'S1 ' : 'S2 ') + '2. ' + p.permutation)
                socket.end(str, 'ascii');
	    }
        );
        
        socket.on('error', function(err){
            console.log(err);
        });
        if(choice == 'SERVER1'){
            socket.on('data', function(data){
                var winner = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
		winner = content.shuffledTimeslots[winner];
		console.log('3.' + p.permutation.toString());
                var noIndices = [];
                var i = 4;
                var offset = 7;
                var participant_idx = 0;
                while(participant_idx < content.participants.length){
                    if( (data[i] & (1 << offset)) > 0){
                        noIndices.push(p.permutation[participant_idx]);
                    }
                    i = offset == 0 ? i + 1 : i;
                    --offset;
                    ++participant_idx;
                }
                console.log('winner: ' + winner + ' no sayers: ' + noIndices.toString());
                content.pollStatus = POLL_ENDED;
                content.winner = winner;
                content.noIndices = noIndices;
                fs.writeFileSync(pollPath, JSON.stringify(content));
            });
        }
        if(choice == 'SERVER1'){
            socket1 = socket;
        }
        else{
            socket2 = socket;
        }
    }
    writeData('SERVER1');
    writeData('SERVER2');
}

function generateRandomPassword(length){
    var buf = crypto.randomBytes(length);
    var passwd = '';
    var i = 0;
    var r = 0;
    for(; i < length; ++i){
        r = buf[i] % 36;
        if(r < 26){
            //a-z
            passwd += String.fromCharCode(97+r);
        }
        else if(r >= 26 && r < 36){
            //0-9
            passwd += String.fromCharCode(48+r-26);
        }
    }
    return passwd;
}

app.get('/', function (req, res) {
   res.sendFile('doodle.html', {
       root: __dirname
   });
});
//when initiator defined the relevant poll information
app.post('/', function(req, res){
    function createShuffledIndexArray(len){
        var arr = new Array(len);
        for(var i = 0; i < len; ++i){
            arr[i] = i;
        }
        return shuffle(arr);
    }
    var i = 0;
    var adminIdx = -1;
    if(req.body.toJSON !== undefined){
        return;
    }
    if(req.body.participants.length < 1){
        return;
    }
    //remove duplicate participants
    req.body.participants = req.body.participants.split(';');
    req.body.participants.sort();
    for(i = 0; (i+1) < req.body.participants.length; ++i){
        if(req.body.participants[i] == req.body.participants[i+1]){
            req.body.participants.splice(i+1, 1)
        }
    }
    req.body.passwords = new Array(req.body.participants.length);
    //generate a random unique string part (referred as password) for each participant
    for(i = 0; i < req.body.participants.length; ++i){
        //if poll initiator (referred as admin) is within participants set adminIdx accordingly
        if(req.body.admin == req.body.participants[i]){
            adminIdx = i;
        }
        req.body.passwords[i] = (i+1) + '-' + generateRandomPassword(passwordLength);
    }
    //poll initiator was not in participants, so add him and set adminIdx accordingly
    if(adminIdx == -1){
        req.body.participants.push(req.body.admin);
        req.body.passwords.push((i+1) + '-' + generateRandomPassword(passwordLength));
        adminIdx = i;
    }
    //create default data for each participant
    req.body.maskedData = new Array(req.body.participants.length);
    req.body.randomData = new Array(req.body.participants.length);
    //create shuffled idices for each participant and timeslot
    req.body.shuffledParticipants = createShuffledIndexArray(req.body.participants.length);
    req.body.shuffledTimeslots = createShuffledIndexArray(req.body.data.match(/;/g).length);
    req.body.adminIndex = adminIdx;
    req.body.pollStatus = POLL_RUNNING;
    fs.writeFileSync('polls/poll' + pollNumber + '.json', JSON.stringify(req.body));
    res.redirect('/poll' + pollNumber + '/' + req.body.passwords[adminIdx]);
    fs.writeFileSync('pollNumber.txt', '' + (++pollNumber));
});

//checks if accessKey represents an admin key. However, this does not check whether the accessKey is valid.
function isAdmin(accessKey, obj){
    return parseInt(accessKey.substring(0, accessKey.indexOf('-'))) === (obj.adminIndex + 1);
}
//checks if accessKey is valid 
function checkAccessKey(accessKey, obj){
    var userID = parseInt(accessKey.substring(0, accessKey.indexOf('-')))-1;
    var accessGranted = false;
    var i;
    if(obj.passwords.length <= userID){
        //set userID to 0 to make a fake comparison
        userID = 0;
    }
    //check all characters to prevent a timing attack
    for(i = 0; i < obj.passwords[userID].length; ++i){
        accessGranted = accessGranted || (accessKey.charAt(i) == obj.passwords[userID].charAt(i));
    }
    if(!accessGranted){
        return -1;
    }
    else{
        return userID;
    }
}

function getPickTimeSite(obj){
    return '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">' +
            '<html>' +
            '<head>' +
                '<meta content="text/html; charset=ISO-8859-1" http-equiv="content-type">' +
                '<title>sec_doodle</title>' +
                '<link rel="stylesheet" href="/styles.css" type="text/css">' +
                '<script language="JavaScript" type="text/javascript" src="/jsbn.js"></script>' +
                '<script language="JavaScript" type="text/javascript" src="/prng4.js"></script>' +
                '<script language="JavaScript" type="text/javascript" src="/rng.js"></script>' +
                '<script language="JavaScript" type="text/javascript" src="/rsa.js"></script>' +
                '<script language="Javascript" type="text/javascript" src="/pick_time.js"></script>' +
            '</head>' +
            '<body>' +
                '<div id="pick_time_container">' +
                '<input id="dates" type="hidden" value="' + obj.data + '">' +
                '</div>' + 
                '<div id="submit_box">' +
                '<form id="masked_form"  method="post">' +
                    '<input id="masked" name="masked_data" type="hidden">' +
                    '<input id="random" name="random_data" type="hidden">' +
                '</form>' + 
                '</div>' +
            '</body>' +
            '<script>' +
                'var pubkeyMasked = {e : "' + pubkeyServer1.e + '", N : "' + pubkeyServer1.N + '"};' +
                'var pubkeyRandom = {e : "' + pubkeyServer2.e + '", N : "' + pubkeyServer2.N + '"};' +
                'var shuffledIdx = [' + obj.shuffledTimeslots + '];' +
                'generateTable();' +
            '</script>' +
            '</html>';
}

function getAdminSite(obj){
    return '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">' +
            '<html>' +
            '<head>' +
                '<meta content="text/html; charset=ISO-8859-1" http-equiv="content-type">' +
                '<title>sec_doodle</title>' +
                '<link rel="stylesheet" href="/styles.css" type="text/css">' +
                '<script language="JavaScript" type="text/javascript" src="/jsbn.js"></script>' +
                '<script language="JavaScript" type="text/javascript" src="/prng4.js"></script>' +
                '<script language="JavaScript" type="text/javascript" src="/rng.js"></script>' +
                '<script language="JavaScript" type="text/javascript" src="/rsa.js"></script>' +
                '<script language="Javascript" type="text/javascript" src="/pick_time.js"></script>' +
            '</head>' +
            '<body>' +
                '<div id="pick_time_container">' +
                '<input id="dates" type="hidden" value="' + obj.data + '">' +
                '</div>' + 
                '<div id="submit_box">' +
                '<form id="masked_form"  method="post">' +
                    '<input id="masked" name="masked_data" type="hidden">' +
                    '<input id="random" name="random_data" type="hidden">' +
                '</form>' + 
                '</div>' +
            '</body>' +
            '<script>' +
                'var pubkeyMasked = {e : "' + pubkeyServer1.e + '", N : "' + pubkeyServer1.N + '"};' +
                'var pubkeyRandom = {e : "' + pubkeyServer2.e + '", N : "' + pubkeyServer2.N + '"};' +
                'var shuffledIdx = [' + obj.shuffledTimeslots + '];' +
                'generateTable();' +
            '</script>' +
            '</html>';
}

function getPollWaitingResultSite(){
    return 'The poll ended. Calculating result. Please try again later.';
}

function pollEndedSite(obj, isAdmin){
    var dateTime = obj.data.split(';')[obj.winner].split(' ');
    var date = new Date(dateTime[0]);
    var time = '';
    if(dateTime.length == 2){
        time = dateTime[1].replace('-', ' - ');
    }
    else if(dateTime.length != 1 || dateTime.length != 2){
        console.log('winning time does not correspond to expected standard, which is yyyy/mm/dd [hh:mm[-hh:mm]]');
    }
    var adminSupplement = '';
    if(isAdmin){
        adminSupplement = '<div class="result_time_no_box">' + 
                              '<div class="result_time_no_box_header">' +
                                'Participants not available:' + 
                              '</div>' +
                          '</div>';
        obj.noIndices.forEach(function(p){
            adminSupplement += '<div class="result_time_participant">' + obj.participants[p] + '</div>';
        });
        adminSupplement += '</div>';
    }
    var result = 
    '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">' +
    '<html>' +
      '<head>' +
        '<meta content="text/html; charset=ISO-8859-1" http-equiv="content-type">' +
        '<title>doodle</title>' + 
        '<link rel="stylesheet" href="/styles.css" type="text/css">' +
      '</head>' +
      '<body>' +
        '<h1>Scheduled time</h1>' +
        '<div class="result_time_container">' + 
          '<div class="pick_time_date_box">' +
            '<div class="pick_time_month">' + monthNames[date.getMonth()] + ' ' + date.getFullYear() + '</div>' +
            '<div class="pick_time_date">' + date.getDate() + '</div>' + 
            '<div class="pick_time_day">' + dayNames[date.getDay()] + '</div>' + 
            '<div class="pick_time_time">' + time + '</div>' + adminSupplement + 
          '</div>' +
        '</div>' + 
      '</body>' +
    '</html>';
    return result;
}

function getPollEndedSite(obj){
    return pollEndedSite(obj, false);
}

function getPollEndedAdminSite(obj){
    return pollEndedSite(obj, true);
}

app.get('/poll:pollID/:accessKey', function(req, res){
    fs.readFile('polls/poll' + req.params.pollID + '.json', function(err, data){
        if(err){
            console.log('could not open file');
            res.send('error');
            return;
        }
        var obj = JSON.parse(data);
        var userID = checkAccessKey(req.params.accessKey, obj);
        var admin = isAdmin(req.params.accessKey, obj);
        if(userID < 0){
            res.status(400);
            res.send('Permission Denied');
            return;
        }
        //send page to allow participant to select his preferred times
        if(obj.pollStatus === POLL_RUNNING && !admin){
            res.send(getPickTimeSite(obj));
        }
        else if(obj.pollStatus === POLL_RUNNING && admin){
            res.send(getAdminSite(obj));
        }
        else if(obj.pollStatus === POLL_WAITING_RESULT){
            res.send(getPollWaitingResultSite());
        }
        else if(obj.pollStatus === POLL_ENDED && !admin){
            res.send(getPollEndedSite(obj));
        }
        else if(obj.pollStatus === POLL_ENDED && admin){
            res.send(getPollEndedAdminSite(obj));
        }
        else{
            res.send('error');
        }
    });
});
//when a participant has made his selections
app.post('/poll:pollID/:accessKey', function(req, res){
    fs.readFile('polls/poll' + req.params.pollID + '.json', function(err, data){
        if(err){
            console.log('could not open file');
            res.send('error');
            return;
        }
        var obj = JSON.parse(data);
        var userID = checkAccessKey(req.params.accessKey, obj);
        if(userID < 0){
            res.status(400);
            res.send('Permission Denied');
            return;
        }
        obj.maskedData[userID] = req.body.masked_data;
        obj.randomData[userID] = req.body.random_data;
        fs.writeFileSync('polls/poll' + req.params.pollID + '.json', JSON.stringify(obj));
        res.sendFile('thank_you.html', {
            root: __dirname
        });
        //if every participant made his selection, start evealuating the poll
	if(obj.maskedData.every(function(currentValue){
            return currentValue !== null;
        })){
            console.log('evaluation of poll %d started', req.params.pollID);
            obj.pollStatus = POLL_WAITING_RESULT;
            sendPollInputs('polls/poll' + req.params.pollID + '.json');
        }
    });
});

function getChangeParticipantSite(obj){
    var formfieldValue = '';
    obj.participants.forEach(function(p){
        formfieldValue = p + '\n\r';
    });
    return
    '<html>' +
        '<head>' +
            '<meta content="text/html; charset=ISO-8859-1" http-equiv="content-type">' +
            '<title>sec_doodle</title>' +
            '<script language="Javascript" type="text/javascript" src="create_poll.js"></script>' +
        '</head>' +
        '<body>' +
            '<form>' +
                '<div class="formfield_container">' +
                    '<textarea name="newParticipants" value="'+ formfieldValue + '"></textarea>' +
                '</div>' +
                '<input class="continuebutton" type="submit" value="Submit">' +
            '</form>' +
        '</body>' +
    '</html>';
}

app.get('/poll:pollID/:accessKey/changeparticipants', function(req, res){
    fs.readFile('polls/poll' + req.params.pollID + '.json', function(err, data){
        if(err){
            console.log('could not open file');
            res. send('error');
            return;
        }
        var obj = JSON.parse(data);
        if(!isAdmin(req.params.accessKey, obj) || checkAccessKey(req.params.accessKey, obj) < 0){
            res.status(400);
            res.send('Permission Denied');
            return;
        }
        res.send(getChangeParticipantSite(obj));
    });
});

app.post('/poll:pollId/:accessKey/changeparticipants', function(req, res){
    fs.readFile('polls/poll' + req.params.pollID + '.json', function(err, data){
        if(err){
            console.log('could not open file');
            res. send('error');
            return;
        }
        var obj = JSON.parse(data);
        if(!isAdmin(req.params.accessKey, obj) || checkAccessKey(req.params.accessKey, obj) < 0){
            res.status(400);
            res.send('Permission Denied');
            return;
        }
        req.body.newParticipants.sort();
        obj.participants.sort();
        var i = 0;
        var j = 0;
        while(i < req.body.newParticipants.length){
            if(req.body.participants[i] == obj.participants[j]){
                ++i;
                ++j;
            }
            //new participant i inserted
            else if(req.body.participants[i] < obj.participants[j]){
                obj.passwords.push((obj.participants.length+1) + '-' + generateRandomPassword(passwordLength));
                obj.participants.push(req.body.participants[i]);
                obj.shuffledParticipants.push(obj.shuffledParticipants.length);
                obj.maskedData.push(null);
                obj.randomData.push(null);
                ++i;
                ++j;
            }
            //old participant j deleted
            else if(req.body.participants[i] > obj.participants[j]){
                //only remove participant if participant is not an admin
                if(j != adminIdx){
                    obj.password.splice(j, 1);
                    obj.participants.splice(j, 1);
                    obj.shuffledParticipants.pop();
                    obj.maskedData.splice(j, 1);
                    obj.randomData.splice(j, 1);
                    ++i;
                }
            }
        }
        for(var i = 0; i < obj.shuffledParticipants.length; ++i){
            obj.shuffledParticipants[i] = i;
        }
        obj.shuffledParticipants = shuffle(obj.shuffledParticipants);
    });
});

var server = https.createServer(
    {
        key : fs.readFileSync('javascriptserver-key.pem'),
        cert : fs.readFileSync('javascriptserver-cert.pem'),
        passphrase : 'TU-DA:Bsc.Thesis2017'
    },
    app
).listen(8443);

http.createServer(function (req, res) {
    res.writeHead(301, { "Location": "https://" + req.headers['host'] + req.url });
    res.end();
}).listen(8080);
