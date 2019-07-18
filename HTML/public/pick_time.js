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

  var shortDayNames = [
    'Sunday',
    'Monday',
    'Tuesday',
    'Wednesday',
    'Thursday',
    'Friday',
    'Saturday'
  ];

  var YES = 0;
  var NO = 3;
  var MAYBE = 1;

  var selections = [];

  function generateTable(){
    var scrollTableContainer = document.createElement('DIV');
    var scrollTableDiv = document.createElement('DIV');
    var tableColumn =  document.createElement('DIV');
    var continueContainer = document.createElement('DIV');
    var continueButton = document.createElement('BUTTON');
    var idx = 0;

    tableColumn.setAttribute('class', 'pick_time_table_column')
    scrollTableContainer.setAttribute('class', 'scroll_table_container');
    scrollTableDiv.setAttribute('class', 'scroll_table');
    continueContainer.setAttribute('class', 'pick_time_continue_container');
    continueButton.setAttribute('class', 'pick_time_done');
    continueButton.setAttribute('type', 'button');

    continueButton.addEventListener('click', sendChoices);

    function addColumn(startDate, endTime, isStartTimeSet, idx){
        function createSvgCrossHTML(){
          return '<svg width="30" height="30" viewbox="0 0 30 30">' +
                    '<path d="M0 0l30 30Z" stroke-width="2" stroke="black" fill="none"></path>' + 
                    '<path d="M0 30l30 -30Z" stroke-width="2" stroke="black" fill="none"></path>' +
                  '</svg>';
        }
        
        var row = document.createElement('DIV');
        var month = document.createElement('DIV');
        var date = document.createElement('DIV');
        var day = document.createElement('DIV');
        var timeBox = document.createElement('DIV');
        var time = document.createElement('DIV');
        var yesNoMaybe = document.createElement('DIV');
        var yes = document.createElement('DIV');
        var no = document.createElement('DIV');
        var maybe = document.createElement('DIV');
        var yesText = document.createElement('DIV');
        var noText = document.createElement('DIV');
        var maybeText = document.createElement('DIV');

        row.setAttribute('class', 'pick_time_table_row');
        timeBox.setAttribute('class', 'pick_time_date_box');
        month.setAttribute('class', 'pick_time_month');
        date.setAttribute('class', 'pick_time_date');
        day.setAttribute('class', 'pick_time_day');
        time.setAttribute('class', 'pick_time_time');
        yesNoMaybe.setAttribute('class', 'yes_no_maybe_container');
        yes.setAttribute('class', 'pick_time_option');
        no.setAttribute('class', 'pick_time_option');
        maybe.setAttribute('class', 'pick_time_option');

        month.appendChild(document.createTextNode(monthNames[startDate.getMonth()] + ' ' + startDate.getFullYear()));
        date.appendChild(document.createTextNode(startDate.getDate()));
        day.appendChild(document.createTextNode(shortDayNames[startDate.getDay()]));
        timeBox.appendChild(month);
        timeBox.appendChild(date);
        timeBox.appendChild(day);
        yesText.appendChild(document.createTextNode('Yes'));
        noText.appendChild(document.createTextNode('No'));
        maybeText.appendChild(document.createTextNode('Maybe'));
        yes.appendChild(document.createElement('DIV'));
        yes.appendChild(yesText);
        no.appendChild(document.createElement('DIV'));
        no.appendChild(noText);
        maybe.appendChild(document.createElement('DIV'));
        maybe.appendChild(maybeText);
        yesNoMaybe.appendChild(yes);
        yesNoMaybe.appendChild(no);
        yesNoMaybe.appendChild(maybe);
        if(isStartTimeSet){
          time.appendChild(document.createTextNode('' + startDate.getHours() + ':' + 
                         (startDate.getMinutes() < 10 ? '0' + startDate.getMinutes() : '' + startDate.getMinutes()) + 
                         endTime));
        }
        timeBox.appendChild(time);
        row.appendChild(timeBox);
        row.appendChild(yesNoMaybe);
        tableColumn.appendChild(row);


        yes.addEventListener('click', function(){
          selections[idx] = YES;
          yes.firstChild.innerHTML = createSvgCrossHTML();
          no.firstChild.innerHTML = '';
          maybe.firstChild.innerHTML = '';
        });
        no.addEventListener('click', function(){
          selections[idx] = NO;
          yes.firstChild.innerHTML = '';
          no.firstChild.innerHTML = createSvgCrossHTML();
          maybe.firstChild.innerHTML = '';
        });
        maybe.addEventListener('click', function(){
          selections[idx] = MAYBE;
          yes.firstChild.innerHTML = '';
          no.firstChild.innerHTML = '';
          maybe.firstChild.innerHTML = createSvgCrossHTML();
        });
      }
    document.getElementById('dates').value.split(';').forEach(function(e){
      if(e.length == 0){
        return;
      }
      var timeStrings = e.split('-');
      idx = selections.push(NO) - 1;
      if(timeStrings.length == 1){
        addColumn(new Date(timeStrings[0]), '', (timeStrings[0].length > 10), idx);
      }
      else if(timeStrings.length == 2){
        addColumn(new Date(timeStrings[0]), ' - ' + timeStrings[1], (timeStrings[0].length > 10), idx);
      }
      else{
        alert('bug');
      }
    });
    continueButton.appendChild(document.createTextNode('Done'));
    continueContainer.appendChild(continueButton);
    scrollTableDiv.appendChild(tableColumn);
    scrollTableDiv.appendChild(continueContainer);
    document.getElementById('pick_time_container').appendChild(scrollTableDiv);
  }

  function sendChoices(){
    function compress(str){
      function toBase64(charcode){
        if(charcode < 26){
          return String.fromCharCode('A'.charCodeAt(0) + charcode);
        }
        else if(charcode >= 26 && charcode < 52){
          return String.fromCharCode('a'.charCodeAt(0) + charcode - 26);
        }
        else if(charcode >= 52 && charcode < 62){
          return String.fromCharCode('0'.charCodeAt(0) + charcode - 52);
        }
        else if(charcode == 62){
          return '+';
        }
        else if(charcode == 63){
          return '/';
        }
        else{
          alert('bug: charcode should not be bigger than 64');
        }
      }
      var result = '';
      var charcode = 0;
      for(var i = 0; (i + 2) < str.length; i += 3){
        charcode = (str.charCodeAt(i) - '0'.charCodeAt(0)) << 4;
        charcode = charcode | ((str.charCodeAt(i+1) - '0'.charCodeAt(0)) << 2);
        charcode = charcode | ((str.charCodeAt(i+2) - '0'.charCodeAt(0)));
        result += toBase64(charcode);
      }
      if(i < str.length){
        charcode = (str.charCodeAt(i) - '0'.charCodeAt(0)) << 4;
      }
      if((i + 1) < str.length){
        charcode = charcode | ((str.charCodeAt(i+1) - '0'.charCodeAt(0)) << 2);
      }
      result += (i < str.length) ? toBase64(charcode) : '';
      return result;
    }
    var maskedData = document.getElementById('masked');
    var randomData = document.getElementById('random');
    var r = 0;
    var mask;
    var rand;
    var enc_masked = new RSAKey();
    var enc_random = new RSAKey();
    enc_masked.setPublic(pubkeyMasked.N, pubkeyMasked.e);
    enc_random.setPublic(pubkeyRandom.N, pubkeyRandom.e);
    mask = '';
    rand = '';
    //shuffle selections according to shuffledIdx received from server
    for(var i = 0; i < selections.length; ++i){
      var tmp = selections[i];
      selections[i] = selections[shuffledIdx[i]];
      selections[shuffledIdx[i]] = selections[i];
    }
    selections.forEach(function(s){
      r = Math.floor(Math.random() * 4);
      mask +=  r ^ s;
      rand += r;
    });
    maskedData.value = enc_masked.encrypt(compress(mask));
    randomData.value = enc_random.encrypt(compress(rand));
    document.getElementById('masked_form').submit();
  }
