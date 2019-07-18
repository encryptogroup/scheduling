    var calendar;
    var select_times;
    var cont = initialize_select_dates;
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
    var shortMonthNames = [
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec'
    ];
    var today = new Date();
    var monthPrototype = {
      month : 0,
      year : 0,
      selectedDates : 0,
      previousMonth : undefined,
      nextMonth : undefined,
      setDay : function(day){
        this.selectedDates = this.selectedDates | (1 << (day-1));
      },
      resetDay : function(day){
        this.selectedDates = this.selectedDates & (~(1 << (day-1)));
      },
      isSelected : function(day){
        return (this.selectedDates & (1 << (day-1))) != 0;
      }
    };
    var selectedMonth = Object.create(monthPrototype);
    
    function formatMonth(n){
      ++n;
      return n < 10 ? '0' + n : '' + n;
    }

    function formatDate(n){
      return n < 10 ? '0' + n : '' + n;
    }

    function sendTimes(){
      function formatHours(str){
        return str.length == 4 ? '0' + str : str;
      }
      var e = select_times.childNodes;
      var s = '';
      var i = 0;
      var j = 0;
      var start = '';
      var end = '';
      var inputs = undefined;
      var d = undefined;
      var t = undefined;
      var continueform = document.getElementById('continueform');
      var hiddenDates = document.getElementById('hidden_dates');
      hiddenDates.value = '';
      for(; i < e.length; ++i){
        t = e[i].childNodes[1].firstChild.childNodes;
        for(j = 0; j < t.length-1; ++j){
          inputs = t[j].firstChild;
          d = new Date(inputs.firstChild.getAttribute('datetime'));
          start = inputs.firstChild.getAttribute('datetime') + 
                  (inputs.firstChild.firstChild.value.length > 0 ? 
                    ' ' + formatHours(inputs.firstChild.firstChild.value) : 
                    ''
                  );
          if(inputs.childNodes[2].value.length > 0){
            end = '-' + formatHours(inputs.childNodes[2].value);
          }
          else{
            end = '';
          }
          hiddenDates.value += start + end + ';';
        }
      }
      document.getElementById('continueform').submit();
    }

    function gotoPreviousMonth(){
      if(selectedMonth.previousMonth === undefined){
        selectedMonth.previousMonth = Object.create(monthPrototype);
        selectedMonth.previousMonth.month = (selectedMonth.month + 11) % 12;
        selectedMonth.previousMonth.year = selectedMonth.month == 0 ? selectedMonth.year - 1 : selectedMonth.year;
        selectedMonth.previousMonth.nextMonth = selectedMonth;
      }
      selectedMonth = selectedMonth.previousMonth;
      printCalendarMonth(new Date(selectedMonth.year, selectedMonth.month, 1));
    }

    function gotoNextMonth(){
      if(selectedMonth.nextMonth === undefined){
        selectedMonth.nextMonth = Object.create(monthPrototype);
        selectedMonth.nextMonth.month = (selectedMonth.month + 1) % 12;
        selectedMonth.nextMonth.year = selectedMonth.month == 11 ? selectedMonth.year + 1 : selectedMonth.year;
        selectedMonth.nextMonth.previousMonth = selectedMonth;
      }
      selectedMonth = selectedMonth.nextMonth;
      printCalendarMonth(new Date(selectedMonth.year, selectedMonth.month, 1));
    }

    function selectDate(date){
      function startWithMonday(day){
        return (day + 6) % 7;
      }
      var firstDayOfMonth = new Date(selectedMonth.year, selectedMonth.month, 1);
      //skip first row if selected weekday is not in the same week
      var row = startWithMonday(date.getDay()) < startWithMonday(firstDayOfMonth.getDay()) ? 1 : 0;
      //calculate the week we're in
      row += Math.floor((date.getDate() - 1)/7);
      var node = calendar.firstChild.childNodes[1].childNodes[row].childNodes[startWithMonday(date.getDay())];
      if(node.className.includes(' selected')){
        node.className = node.className.replace(' selected', '');
        selectedMonth.resetDay(date.getDate());
        removeSelectTime(date);
      }
      else{
        node.className += ' selected';
        selectedMonth.setDay(date.getDate());
        addSelectTime(date);
      }
    }
    
    
    function findIndex(date, parent){
      function func_retrieve_date(node){
        return new Date(node.childNodes[1].firstChild.firstChild.firstChild.firstChild.getAttribute('datetime'));
      }
      var elements = parent.childNodes;
      var l = 0;
      var r = elements.length-1;
      var m = 0; 
      if(r < l){
        return -1;
      }
      while(l < r){
        m = Math.floor((l+r)/2);
        if(date.getTime() < func_retrieve_date(elements[m]).getTime()){
          r = m-1;
        }
        else if(date.getTime() > func_retrieve_date(elements[m]).getTime()){
          l = m+1;
        }
        else{
          return m; 
        }
      }
      //l and r are equal now
      if(date.getTime() < func_retrieve_date(elements[l]).getTime()){
        return l;
      }
      else if(date.getTime() > func_retrieve_date(elements[l]).getTime()){
        return l+1;
      }
      else{
        return l;
      }
    }

    function removeSelectTime(date){
      var idx = findIndex(date, select_times);
      select_times.removeChild(select_times.childNodes[idx]);
    }

    function addSelectTime(date){
      var h3 = document.createElement('H3');

      var outerDiv = document.createElement('DIV');

      var middleDiv = document.createElement('DIV');
      middleDiv.setAttribute('class', 'input_container');

      var div = document.createElement('DIV');
      div.setAttribute('class', 'time_input');

      var time = document.createElement('TIME');
      time.setAttribute('datetime', '' + date.getFullYear() + '/' + formatMonth(date.getMonth()) + '/' + formatDate(date.getDate()));

      var start_in = document.createElement('INPUT');
      start_in.setAttribute('class', 'start_input');
      start_in.setAttribute('type', 'text');
      start_in.setAttribute('placeholder', 'hh:mm');
      start_in.setAttribute('value', '');
      start_in.setAttribute('required', 'required');
      start_in.setAttribute('size', '5');

      var sep = document.createElement('SPAN');
      sep.setAttribute('class', 'seperator');

      var end_in = document.createElement('INPUT');
      end_in.setAttribute('class', 'end_input');
      end_in.setAttribute('type', 'text');
      end_in.setAttribute('placeholder', 'hh:mm');
      end_in.setAttribute('value', '');
      end_in.setAttribute('size', '5');

      var closeButton = document.createElement('BUTTON');
      closeButton.setAttribute('type', 'button');
      closeButton.setAttribute('class', 'close_button silent_button');


      var button = document.createElement('BUTTON');
      button.setAttribute('type', 'button');
      button.setAttribute('class', 'more_times_button silent_button');

      var ul = document.createElement('UL');

      var li = document.createElement('LI');
      li.setAttribute('class', 'input_list');

      var button_li = document.createElement('LI');
      button_li.setAttribute('class', 'button_list');

      h3.appendChild(document.createTextNode('' + shortMonthNames[date.getMonth()] + ' ' + date.getDate()));
      sep.appendChild(document.createTextNode('-'));
      time.appendChild(start_in);
      closeButton.appendChild(document.createTextNode('X'));
      button.appendChild(document.createTextNode('+ Add more times'));
      button_li.appendChild(button);
      div.appendChild(time);
      div.appendChild(sep);
      div.appendChild(end_in);
      div.appendChild(closeButton);
      li.appendChild(div);
      ul.appendChild(li);
      ul.appendChild(button_li);
      middleDiv.appendChild(ul);
      outerDiv.appendChild(h3);
      outerDiv.appendChild(middleDiv);

      var idx = findIndex(date, select_times);
      if(idx >= 0){
        select_times.insertBefore(outerDiv, select_times.childNodes[idx]);
      }
      else{
        select_times.appendChild(outerDiv);
      }

      function addListeners(startInput, endInput, closeButton){
        function isIllegalPartialInput(str){
          var parsedPrefix = parseInt(str, 10);
          return (str.length > 0 && (str.charAt(0) < '0' || str.charAt(0) > '9'))
                  || (str.length > 1 && (str.charAt(1) < '0' || str.charAt(1) > '9') && str.charAt(1) != ':')
                  || (str.length > 1 && (parsedPrefix < 0 || parsedPrefix > 23))
                  || (str.length > 2 && str.charAt(1) != ':' && str.charAt(2) != ':')
                  || (str.length > 2 && str.charAt(1) == ':' && (str.charAt(2) < '0' || str.charAt(2) > '5'))
                  || (str.length > 3 && str.charAt(2) == ':' && (str.charAt(3) < '0' || str.charAt(3) > '5'))
                  || (str.length > 3 && str.charAt(1) == ':' && (str.charAt(3) < '0' || str.charAt(3) > '9'))
                  || (str.length > 4 && str.charAt(2) == ':' && (str.charAt(4) < '0' || str.charAt(4) > '9'))
                  || (str.length > 4 && str.charAt(1) == ':')
                  || (str.length > 5);
        }
        function isIllegalInput(str){
          var parsedPrefix = parseInt(str, 10);
          return (str.length > 5)
                  || (str.length < 4)
                  || (str.length == 4 && charAt(1) != ':')
                  || (str.length == 5 && charAt(2) != ':')
                  || (parsedPrefix < 0 || parsedPrefix > 23)
                  || (str.length == 4 && (charAt(2) < '0' || charAt(2) > '5'))
                  || (str.length == 4 && (charAt(3) < '0' || charAt(3) > '9'))
                  || (str.length == 5 && (charAt(3) < '0' || charAt(3) > '5'))
                  || (str.length == 5 && (charAt(4) < '0' || charAt(4) > '9'))
        }
        function resetIfIllegal(node){
          if(isIllegalInput(node.value)){
            node.value = '';
            return true;
          }
          else{
            return false;
          }
        }
        var preventFalseInput = (function(){
          var oldValue = '';
          return function(node){
            if(isIllegalPartialInput(node.value)){
              node.value = oldValue;
            }
            else{
              oldValue = node.value;
            }
          }
        }());

        startInput.addEventListener('input', function(){
          preventFalseInput(startInput);
        });
        startInput.addEventListener('blur', function(){
          resetIfIllegal(startInput);
        });

        endInput.addEventListener('input', function(){
          preventFalseInput(endInput);
        });
        endInput.addEventListener('blur', function(){
          resetIfIllegal(endInput);
        });
        closeButton.addEventListener('click', function(){
          if(ul.childNodes.length > 2){
            ul.removeChild(closeButton.parentNode.parentNode);
          }
          else{
            startInput.value = '';
            endInput.value = '';
          }
        });
      }

      addListeners(start_in, end_in, closeButton);
      
      button.addEventListener('click', function(){
        var l = li.cloneNode(true);
        var s = l.firstChild.childNodes[0].firstChild;
        var e = l.firstChild.childNodes[2];
        s.value = '';
        e.value = '';
        addListeners(s, e, l.firstChild.childNodes[3]);
        ul.insertBefore(l, button_li);
      });
    }

    function printCalendarMonth(date){
      function isWeekend(day){
        return (day % 7) == 6 || (day % 7) == 0;
      }
      function isPast(date){
        return today.getTime() > new Date(date.getFullYear(), date.getMonth(), i).getTime();
      }
      selectedMonth.month = date.getMonth();
      selectedMonth.year = date.getFullYear();
      var d = new Date(selectedMonth.year, selectedMonth.month, 1);
      var newTable = 
      '<table id="tbl" role="grid" style="text-align: left; margin-left: auto; margin-right: auto;" border="0" cellpadding="4" cellspacing="4">' +
      '<thead>' +
        '<tr>' +
          '<th style="vertical-align: top;">' + 
            '<button type="button" id="arrow_left" class="silent_button" onclick="gotoPreviousMonth()">' +
              '<svg viewBox="0 0 24 24" width="24px" height="24px">' +
                '<path d="M15 5l-5 5Z" stroke-width="2px" stroke="black" fill="none"></path>' +
                '<path d="M10 10l5 5Z" stroke-width="2px" stroke="black" fill="none"></path>' + 
              '</svg>' +
            '</button>' +
          '</th>' +
          '<th style="vertical-align: top;" colspan="5">' + monthNames[selectedMonth.month] + ' ' + selectedMonth.year + '</th>' +
          '<th style="vertical-align: top;">' +
            '<button type="button" id="arrow_right" class="silent_button" onclick="gotoNextMonth()">' +
              '<svg viewBox="0 0 24 24" width="24" height="24">' +
                  '<path d="M15 5l 5 5Z" stroke-width="2px" stroke="black" fill="none"></path>' +
                  '<path d="M20 10l-5 5Z" stroke-width="2px" stroke="black" fill="none"></path>' + 
              '</svg>' +
            '</button>' +
          '</th>' +
        '<tr>' +
          '<th style="vertical-align: top;" class="weekday">M<br></th>' +
          '<th style="vertical-align: top;" class="weekday">T<br></th>' +
          '<th style="vertical-align: top;" class="weekday">W<br></th>' +
          '<th style="vertical-align: top;" class="weekday">T<br></th>' +
          '<th style="vertical-align: top;" class="weekday">F<br></th>' +
          '<th style="vertical-align: top;" class="weekend">S<br></th>' +
          '<th style="vertical-align: top;" class="weekend">S<br></th>' +
        '</tr></thead><tbody>';
      var currentDay = 1;
      var i;
      for(; currentDay != d.getDay(); currentDay = (currentDay+1)%7){
        //<tr> only on the first iteration
        //no empty line will be printed, therefore no </tr> in this loop
        if(currentDay == 1){
          newTable += '<tr>';
        }
        if(isWeekend(currentDay)){
          newTable += '<td style="vertical-align: top;" class="whitespace weekend"></td>';
        }
        else{
          newTable += '<td style="vertical-align: top;" class="whitespace weekday"></td>';
        }
      }
      //the last day of the current month
      d.setMonth(d.getMonth()+1, 0);
      for(i = 1; i <= d.getDate(); ++i){
        //beginning of a week means new row
        if((currentDay % 7) == 1){
          newTable += '<tr>';
        }
        var classes = 'class=';
        classes += '"' +
          (isWeekend(currentDay) ? 'weekend' : 'weekday') + 
          (isPast(date) ? ' past' : ' selectable') + 
          (today.getFullYear() == date.getFullYear() && today.getMonth() == date.getMonth() && today.getDate() == i ? ' currentDay' : '') + 
          (selectedMonth.isSelected(i) ? ' selected' : '') + '"';
        newTable += '<td style="vertical-align: top;"' + 
                    classes + 
                    (!isPast(date) ? ' onclick="selectDate(new Date(selectedMonth.year, selectedMonth.month, ' + i + '))">' : '>') + 
                    '<div id="date_entry"><span display="inline-block">' + i + '</span></div></td>';
        //end of week means end of row
        if((currentDay % 7) == 0){
          newTable += '</tr>';
        }
        currentDay = (currentDay + 1) % 7;
      }
      //print empty cells until sunday
      for(; currentDay != 0; currentDay = (currentDay + 1) % 7){
        if(isWeekend(currentDay)){
          newTable += '<td style="vertical-align: top;" class="whitespace weekend"></td>';
        }
        else{
          newTable += '<td style="vertical-align: top;" class="whitespace weekday"></td>';
        }
        //print empty cell for sunday
        if(currentDay == 6){
          newTable += '<td style="vertical-align: top;" class="whitespace weekend"><br></td></tr>';
        }
      }
      newTable += '</tbody></table>';
      calendar.innerHTML = newTable;
    }

    function initialize_select_dates(){
      var s = 
          '<div id="two_elements">' +
            '<div id="transparentbox">' +
              '<div id="calendarbox">' +
              '</div>' +
            '</div>' +
            '<section>' +
              '<div id="select_times">' +
              '</div>' +
            '</section>' +
          '</div>';
      var continueform = document.getElementById('continueform');
      var titleInputContainer = document.getElementById('title_input_container');
      //title
      continueform.childNodes[3].value = titleInputContainer.childNodes[0].firstChild.value;
      //admin
      continueform.childNodes[5].value = titleInputContainer.childNodes[1].firstChild.value;
      //location
      continueform.childNodes[7].value = titleInputContainer.childNodes[2].firstChild.value;
      //participants
      continueform.childNodes[9].value = titleInputContainer.childNodes[3].firstChild.value.replace(/[\s,;]+/g, ';');
      var cb = document.getElementById('contentbox');
      cb.removeChild(cb.firstChild);
      cb.innerHTML = s + cb.innerHTML;
      calendar = document.getElementById('calendarbox');
      select_times = document.getElementById('select_times');
      cont = sendTimes;
      var cur = new Date();
      today.setHours(0, 0, 0, 0);
      printCalendarMonth(new Date(cur.getFullYear(), cur.getMonth(), 7));
      
    }
    function initialize_start_poll(){
      var s = 
        '<div id="title_input_container">' +
          '<div class"formfield_container">' +
            '<input id="titleinput" class="input_border" type="text" placeholder="Title">' +
          '</div>' +
          '<div class="formfield_container">' +
            '<input id="adminmail" class="input_border" type="text" placeholder="Your email">' +
          '</div>' +
          '<div class="formfield_container">' +
            '<input id="locationinput" class="input_border" type="text" placeholder="location (optional)">' +
          '</div>' +
          '<div class="formfield_container">' +
            '<textarea id="participants" placeholder="Email of participants"></textarea>' +
          '</div>' +
        '</div>';
        var cb = document.getElementById('contentbox');
        cb.innerHTML = s + cb.innerHTML;
    }
