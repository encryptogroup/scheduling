# Privacy-Preserving Event Scheduling
Privacy-preserving event scheduling system

By *Ágnes Kiss*, *Oliver Schick* and *Thomas Schneider* ([ENCRYPTO](http://www.encrypto.de), TU Darmstadt) in [SECRYPT'19](http://www.secrypt.icete.org/). Paper available [here](http://encrypto.de/papers/KSS19.pdf), poster available [here](https://encrypto.de/papers/KSS19Poster.pdf).

### Features
---

Our implementation for privacy-preserving event scheduling is based on secure computation, more specifically, on the ABY framework (https://github.com/encryptogroup/ABY).

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

### Requirements
---
The requirements are the same as that of https://github.com/encryptogroup/ABY and you need to install Node.js for the web application by running
```
sudo apt-get install nodejs
sudo apt-get install npm
```
### Building the Scheduling System
Clone a version of [ABY](https://github.com/encryptogroup/ABY) and place the sec_doodle folder in the ```ABY/src/examples``` folder. Add line
```
add_subdirectory(sec_doodle)
```
in ```ABY/src/examples/CMakeLists.txt``` and build the framework according to the instructions [here](https://github.com/encryptogroup/ABY) building the executables also for the example applications. Then, you should have a ```sec_doodle.exe``` file in the ```ABY/build/bin``` folder.

### Running the Scheduling System
Start three terminals and do the following:
* In the first terminal, cd into the HTML folder, and run
```
npm install
node main.js
```
* In the second terminal, cd into the ```ABY/build/bin``` folder, and run
```
./sec_doodle -r 0
```
* In the third terminal, cd into the ```ABY/build/bin``` folder, and run
```
./sec_doodle -r 1
```
* Open a browser and connect with ```https://localhost:8443```.
* Set up the poll following the instructions and submit admin vote (use dummy email addresses, as no email forwarding is in place).
* For each other participant, open in ```HTML/polls``` the file pollxx.json, where xx is the poll number shown in the link. Copy the passwords from the file (stored in the array "passwords") and replace in the link the admins password with that of the participant to be able to vote.
