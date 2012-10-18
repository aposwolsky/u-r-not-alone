// Context precondition:
// expects this.selected to contain a list of friend objects selected
//         this.alLFriends contains all possible friends
//         this.selectedContainer contains a container for a list of selected friends
//         this.clearSelectedButton is the button to clear all selections
//         this.submitButton is the submit button

//URL param extractor based on http://www.jquery4u.com/snippets/url-parameters-jquery/#.UHd9FmlVA_8 -- 10/11/2012
getUrlParam = function(name){
  var results = new RegExp('[\\?&]' + name + '=([^&#]*)').exec(window.location.href);
  return results[1] || 0;
};

submitFriendCheckinForm = function() {
  this.submitButton.button("disable");
  $.mobile.loading( 'show', {});
  var ids = _(this.selected).map(function(x){return x.id;}, this).join("-");
  var fsqCallback = decodeURIComponent(getUrlParam('fsqCallback'));
  var userId = decodeURIComponent(getUrlParam('userId'));
  var checkinId = decodeURIComponent(getUrlParam('checkinId'));
  var accessToken = decodeURIComponent(getUrlParam('access_token'));

  $.ajax({
    url: 'friend-checkin',
    cache: false,
    type: 'POST',
    dataType: "json",
    data: {userId: userId, checkinId: checkinId, access_token: accessToken, selected: ids}
  }).done(_.bind(function(result) {
    this.submitButton.button("enable");
    $.mobile.loading( 'hide', {});
    window.location.href = fsqCallback;
  }, this)).error(_.bind(function() {
    this.submitButton.button("enable");
    $.mobile.loading( 'hide', {});
    // briefly show error message
    $.mobile.showPageLoadingMsg( $.mobile.pageLoadErrorMessageTheme, 'Error, please try again...', true );
    setTimeout( $.mobile.hidePageLoadingMsg, 1500 );
  }, this));
};

updateSelectedInformation = function() {
  var numSelected = this.selected.length;
  this.submitButton.prop("value", "Check them in! (" + numSelected + " selected)").button("refresh");
  this.selectedContainer.empty();
  if (numSelected > 0) {
    var names = _(this.selected).map(function(x){return x.name;}, this).join(", ");
    this.selectedContainer.append(names);
    this.submitButton.button("enable");
    this.clearSelectedButton.show();
  } else {
    this.selectedContainer.append('(none)');
    this.submitButton.button("disable");
    this.clearSelectedButton.hide();
  }
};

clearAllSelected = function() {
  _.each(this.selected, function(selectedObj) {
    removeFriend(selectedObj.id);
  }, this);
};

// precondition: this.selected contains a list of friend objects selected and this.allFriends contains all possible
addFriend = function(userId) {
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
removeFriend = function(userId) {
  this.selected = _(this.selected).filter(function(x) {return x.id != userId;}, this);
  // Update checkbox if necessary
  if ($('#' + userId).prop("checked")) {
    $('#' + userId).prop("checked", false).checkboxradio("refresh");
  }
  updateSelectedInformation();
};

initialize = function() {
  this.selected = [];
  this.selectedContainer = $('#selectedContainer');
  this.clearSelectedButton = $('#clearSelectedButton');
  this.submitButton = $('#submitButton');
  var listContainer = $('#friendList');
  var loadingContainer = $('#friendsLoading');
  var loadedContainer = $('#friendsLoaded');
  var errorContainer = $('#friendsError');
  var userId = decodeURIComponent(getUrlParam('userId'));
  var checkinId = decodeURIComponent(getUrlParam('checkinId'));
  var accessToken = decodeURIComponent(getUrlParam('access_token'));

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
      $(".ui-page").trigger("create"); // formats the checkboxes
    }, this);

    _.each(result.mentions, function(mentionedId) {
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
    this.submitButton.bind("click", _.bind(function(event) {
      submitFriendCheckinForm();
      return false; // we dont' want to process the default post behavior
    }, this));

    this.clearSelectedButton.bind("click", _.bind(function(event) {
      clearAllSelected();
      // Clear the class that makes the button look blue
      this.clearSelectedButton.find('a').removeClass("ui-btn-active")
      return false; // stop work after clearing all selected
    }, this));

    loadingContainer.hide();
    loadedContainer.show();

  }, this)).error(_.bind(function() {
    loadingContainer.hide();
    errorContainer.show();
  }, this));
};
