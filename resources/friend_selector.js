// Context precondition:
// expects this.selected to contain a list of friend objects selected
//         this.maxSelectable contains the max number of friends allowed
//         this.reachedMaxSelected indicates whether the max number of friends have been selected
//         this.allFriends contains all possible friends
//         this.friendChoiceSelection will contain the option selected when on the settings screen

//URL param extractor based on http://www.jquery4u.com/snippets/url-parameters-jquery/#.UHd9FmlVA_8 -- 10/11/2012
function getUrlParam(name){
  var results = new RegExp('[\\?&]' + name + '=([^&#]*)').exec(window.location.href);
  if (results) {
    return results[1] || '';
  } else {
    return '';
  }
};

function saveSettings(userId, accessToken) {
  var allowAll = false;
  var ids = "";
  if (this.friendChoiceSelection == "all") {
    allowAll = true;
    ids = "";
  } else if (this.friendChoiceSelection == "none") {
    allowAll = false;
    ids = "";
  } else if (this.friendChoiceSelection == "some") {
    allowAll = false;
    ids = _(this.selected).map(function(x){return x.id;}, this).join("-");
  }

  $.mobile.loading( 'show', {});

  $.ajax({
    url: 'change-settings',
    cache: false,
    type: 'POST',
    dataType: "json",
    data: {userId: userId, access_token: accessToken, allowAll: allowAll, authorizedFriends: ids}
  }).done(_.bind(function(result) {
    $.mobile.loading( 'hide', {});
    history.back();
  }, this)).error(_.bind(function() {
    $.mobile.loading( 'hide', {});
    // briefly show error message
    $.mobile.showPageLoadingMsg( $.mobile.pageLoadErrorMessageTheme, 'Error, please try again...', true );
    setTimeout( $.mobile.hidePageLoadingMsg, 1500 );
  }, this));
};

function submitFriendCheckinForm(userId, checkinId, accessToken, fsqCallback) {
  $('#submitButton').button("disable");
  $.mobile.loading( 'show', {});
  var ids = _(this.selected).map(function(x){return x.id;}, this).join("-");

  $.ajax({
    url: 'friend-checkin',
    cache: false,
    type: 'POST',
    dataType: "json",
    data: {userId: userId, checkinId: checkinId, access_token: accessToken, selected: ids}
  }).done(_.bind(function(result) {
    $('#submitButton').button("enable");
    $.mobile.loading( 'hide', {});
    window.location.href = fsqCallback;
  }, this)).error(_.bind(function() {
    $('#submitButton').button("enable");
    $.mobile.loading( 'hide', {});
    // briefly show error message
    $.mobile.showPageLoadingMsg( $.mobile.pageLoadErrorMessageTheme, 'Error, please try again...', true );
    setTimeout( $.mobile.hidePageLoadingMsg, 1500 );
  }, this));
};

// This function will update the controls on both the checkin and the settings page
function updateSelectedInformation() {
  var numSelected = this.selected.length;
  var submitButton = $('#submitButton'); // only for the checkin page
  $('#settingsSelectedOption .ui-btn-text').text("Selected list (" + numSelected + ")"); // only on the settings page

  var clearSelectedButton = $('#clearSelectedButton');
  submitButton.text("Check them in! (" + numSelected + " selected)").button("refresh");
  var selectedContainer = $('#selectedContainer');
  selectedContainer.empty();
  if (numSelected >= this.maxSelectable) {
    this.reachedMaxSelected = true;
    _.each($('#friendList').find('.ui-checkbox'), function(checkboxElement) {
      var $checkboxElement = $(checkboxElement);
      if ($checkboxElement.find('.ui-icon-checkbox-off').length > 0) {
        $checkboxElement.addClass('ui-disabled');
      }
    })
  } else if (this.reachedMaxSelected) {
    this.reachedMaxSelected = false;
    $('#friendList').find('.ui-checkbox').removeClass('ui-disabled');
  }
  if (numSelected > 0) {
    var names = _(this.selected).map(function(x){return x.name;}, this).join(", ");
    selectedContainer.append(names);
    submitButton.button("enable");
    clearSelectedButton.show();
  } else {
    selectedContainer.append('(none)');
    submitButton.button("disable");
    clearSelectedButton.hide();
  }
};

function clearAllSelected() {
  _.each(this.selected, function(selectedObj) {
    removeFriend(selectedObj.id);
  }, this);
};

// precondition: this.selected contains a list of friend objects selected and this.allFriends contains all possible
function addFriend(userId) {
  var friendSelected = _(this.allFriends).find(function(x) {return x.id == userId;}, this);
  if (friendSelected) {
    this.selected.push(friendSelected);
    // Sort the selected in the order of allFriends by doing difference
    this.selected = _(this.allFriends).intersect(this.selected);
    // Update checkbox if necessary
    if (!$('#' + userId).prop("checked")) {
      $('#' + userId).prop("checked", true).checkboxradio("refresh");
    }
    updateSelectedInformation();
  }
};

// precondition: this.selected contains a list of friend objects selected
function removeFriend(userId) {
  this.selected = _(this.selected).filter(function(x) {return x.id != userId;}, this);
  // Update checkbox if necessary
  if ($('#' + userId).prop("checked")) {
    $('#' + userId).prop("checked", false).checkboxradio("refresh");
  }
  updateSelectedInformation();
};

function initializeFriendCheckinPage() {
  this.selected = [];
  this.maxSelectable = 5; // Used to disallow a user checking in too many users at once.
  this.reachedMaxSelected = false;
  var listContainer = $('#friendList');
  var loadingContainer = $('#friendsLoading');
  var loadedContainer = $('#friendsLoaded');
  var errorContainer = $('#friendsError');
  var settingsLink = $('#settingsLink');

  var userIdEncoded = getUrlParam('userId');
  var checkinIdEncoded = getUrlParam('checkinId');
  var accessTokenEncoded = getUrlParam('access_token');
  var fsqCallbackEncoded = getUrlParam('fsqCallback');
  var userId = decodeURIComponent(userIdEncoded);
  var checkinId = decodeURIComponent(checkinIdEncoded);
  var accessToken = decodeURIComponent(accessTokenEncoded);
  var fsqCallback = decodeURIComponent(fsqCallbackEncoded);

  loadedContainer.hide();
  errorContainer.hide();
  loadingContainer.show();
  updateSelectedInformation();
  listContainer.empty();
  settingsLink.prop('href', 'settings?userId=' + userIdEncoded + '&access_token=' + accessTokenEncoded );
  settingsLink.removeClass('ui-disabled');

  $.ajax({
    url: 'friendjson',
    cache: false,
    dataType: "json",
    data: {userId: userId, checkinId: checkinId, access_token: accessToken}
  }).done(_.bind(function(result) {
    this.allFriends = result.friendInfo;
    _.each(this.allFriends, function(friend) {
      var newElement = '<li class="checkboxInList">' +
        '<input type="checkbox" id=' + friend.id + ' name="' + friend.id + '" class="custom" />' +
        '<label class="checkboxInList" for="' + friend.id + '">' +
        friend.name + '</label></li>';
      listContainer.append(newElement);
    }, this);
    $(".ui-page").trigger("create"); // formats the checkboxes

    _.each(result.mentions.slice(0, this.maxSelectable), function(mentionedId) {
      addFriend(mentionedId);
    }, this);

    $('#footerSummaryText').text(result.settingsSummary)

    $("input[type='checkbox']").bind("change", _.bind(function(event) {
      var userId = event.target.id;
      var isChecked = event.target.checked;
      if (isChecked) {
        addFriend(userId);
      } else {
        removeFriend(userId);
      }
    }, this));
    $('#submitButton').bind("click", _.bind(function(event) {
      submitFriendCheckinForm(userId, checkinId, accessToken, fsqCallback);
      return false;
    }, this));

    $('#clearSelectedButton').bind("click", _.bind(function(event) {
      clearAllSelected();
      // Clear the class that makes the button look blue
      $('#clearSelectedButton').find('a').removeClass("ui-btn-active")
      return false; // stop work after clearing all selected
    }, this));

    loadingContainer.hide();
    loadedContainer.show();

  }, this)).error(_.bind(function() {
    loadingContainer.hide();
    errorContainer.show();
  }, this));
};

function initializeSettingsPage() {
  this.selected = [];
  this.maxSelectable = 10000;
  this.reachedMaxSelected = false;
  var listContainer = $('#friendList');
  var loadingContainer = $('#settingsLoading');
  var loadedContainer = $('#settingsLoaded');
  var errorContainer = $('#settingsError');

  var userIdEncoded = getUrlParam('userId');
  var accessTokenEncoded = getUrlParam('access_token');
  var userId = decodeURIComponent(userIdEncoded);
  var accessToken = decodeURIComponent(accessTokenEncoded);

  loadedContainer.hide();
  errorContainer.hide();
  loadingContainer.show();
  updateSelectedInformation();
  listContainer.empty();

  $.ajax({
    url: 'settingsjson',
    cache: false,
    dataType: "json",
    data: {userId: userId, access_token: accessToken}
  }).done(_.bind(function(result) {
    // Make sure none are selected to start
    $('input[name=friends-choice]').removeProp("checked", "false").checkboxradio("refresh");

    if (result.permissions.allowAll) {
      $('#settingsFriendSelector').hide();
      $('#all-friends-choice').prop("checked", "checked").checkboxradio("refresh");
      this.friendChoiceSelection = "all";
    } else if (result.permissions.authorizedFriends.length == 0) {
      $('#settingsFriendSelector').hide();
      $('#no-friends-choice').prop("checked", "checked").checkboxradio("refresh");
      this.friendChoiceSelection = "none";
    } else {
      $('#some-friends-choice').prop("checked", "checked").checkboxradio("refresh");
      this.friendChoiceSelection = "some";
      $('#settingsFriendSelector').show();
    }
    this.allFriends = result.friendInfo;
    _.each(this.allFriends, function(friend) {
      var newElement = '<li class="checkboxInList">' +
        '<input type="checkbox" id=' + friend.id + ' name="' + friend.id + '" class="custom" />' +
        '<label class="checkboxInList" for="' + friend.id + '">' +
        friend.name + '</label></li>';
      listContainer.append(newElement);
    }, this);
    $(".ui-page").trigger("create"); // formats the checkboxes

    _.each(result.permissions.authorizedFriends, function(mentionedId) {
      addFriend(mentionedId);
    }, this);

    $("input[type='checkbox']").bind("change", _.bind(function(event) {
      var userId = event.target.id;
      var isChecked = event.target.checked;
      if (isChecked) {
        addFriend(userId);
      } else {
        removeFriend(userId);
      }
    }, this));

    $('#clearSelectedButton').bind("click", _.bind(function(event) {
      clearAllSelected();
      // Clear the class that makes the button look blue
      $('#clearSelectedButton').find('a').removeClass("ui-btn-active")
      return false;
    }, this));

    $('#saveSettingsButton').bind("click", _.bind(function(event) {
      saveSettings(userId, accessToken);
      return false;
    }, this));

    $('input[name=friends-choice]').bind( "change", _.bind(function(event) {
      this.friendChoiceSelection = event.target.value;
      if (event.target.value == 'some') {
        $('#settingsFriendSelector').show();
      } else {
        $('#settingsFriendSelector').hide();
      }
    }, this));

    loadingContainer.hide();
    loadedContainer.show();

  }, this)).error(_.bind(function() {
    loadingContainer.hide();
    errorContainer.show();
  }, this));
};
