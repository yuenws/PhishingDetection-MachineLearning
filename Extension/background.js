chrome.contextMenus.onClicked.addListener(function (word){
  var query = word.linkUrl;
  //chrome.tabs.create({url: query});
  var xhr=new XMLHttpRequest();
  var markup = "url="+query;
  xhr.open("POST"," /*update your own localhost path*/ ",false);
  xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  xhr.send(markup);
  //alert(markup)
  
  //alert(xhr.responseText);

  chrome.runtime.sendMessage({message: "message"}, function() {
    alert("The URL being tested is - "+query +"\n\n"+xhr.responseText);
  });

});


chrome.runtime.onInstalled.addListener(function() {
  chrome.contextMenus.create({
    "id": "start",
    "title": "Check a URL",
    "contexts": ["link"],
  });
});
