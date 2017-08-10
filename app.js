/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict'
const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request');

var reddit = require('redwrap');
var ObjectId = require('mongodb').ObjectID;
var d = new Date();
var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

// Import our models file to the router
var models = require('./models/userModel');
var gmodels = require('./models/goalModel');

// Connect to the database over Mongoose
var mongoose = require('mongoose');
mongoose.connect(process.env.MONGOLAB_URI);

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = process.env.APP_SECRET;

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = process.env.VALIDATION_TOKEN;

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = process.env.PAGE_ACCESS_TOKEN;

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  console.log(senderID);
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;


  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // Create new user or identify user
  models.User.findOne({name:senderID}, function(err, result) {
    if (result == null) {
      console.log("new user");
      var newUser = new models.User({
        name: senderID,
        status: "null",
        numGoals: 0,
        finished: [],
        lastPicTime: 0
      });
      newUser.save(function(err, result) {
        console.log("New user created");
        sendTextMessage(senderID, "Welcome, here is the home screen:")
        sendHome(senderID);
      });
      return;
    }
  });

  // You may get a text or attachment but not both
  var messageText = message.text
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    // Quick Replies
    var payload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, payload);
    if (payload.substring(0,4) == "view") {
      var id = payload.substring(5,payload.length);
      gmodels.Goal.findOne({"_id": ObjectId(id)},
        function(err, result) {
          console.log(result);
          sendGoal(senderID, result);
        });
    } else if (payload.substring(0,4) == "prog") {
      var id = payload.substring(5,payload.length);
      streakProcess(id, "prog", senderID);
      models.User.update({name:senderID},
      {$set:{status:'logging_goal'+id}},
      function(err) {
        sendTextMessage(senderID, "Add a log message to your goal!");
      });
    } else if (payload.substring(0,4) == "logs") {
      var stop = payload.indexOf("!")
      var index = parseInt(payload.substring(4,stop));
      var id = payload.substring(stop+1,payload.length);
      gmodels.Goal.findOne({"_id": ObjectId(id)},
        function(err, result) {
          console.log(result);
          viewLogs(senderID, result, index);
        });
    } else if (payload.substring(0,4) == "no  ") {
      sendTextMessage(senderID, "Deleting canceled, going to home...");
      sendHome(senderID);
    } else if (payload.substring(0,4) == "nf  ") {
      sendTextMessage(senderID, "Finishing canceled, going to home...");
      sendHome(senderID);
    } else if (payload.substring(0,4) == "yes ") {
      // Deleting goal
      var id = payload.substring(5,payload.length);
      gmodels.Goal.remove({"_id": ObjectId(id)},
        function(err, result) {
          if (!err) {
            models.User.findOne({name: senderID},
            function(err, result) {
              models.User.update({name:senderID},
              {$set:{numGoals:result.numGoals - 1}},
              function(err) {
                sendTextMessage(senderID, "Goal deleted! Going to home...");
                sendHome(senderID);
              });
            });
          }
          else {
            sendTextMessage(senderID, "There was an error deleting your goal, please try again, going to home...")
            sendHome(senderID);
          }
        });

    } else if (payload.substring(0,4) == "yef ") {
      var id = payload.substring(5,payload.length);
      // Finishing Goal
      gmodels.Goal.findOne({"_id": ObjectId(id)},
      function(err, goal) {
        models.User.findOne({"name": senderID},
        function(err, user) {
          var d = new Date();
          var oldFin = user.finished;
          oldFin.unshift(String(goal.name + ' 🔥' + goal.total))
          models.User.update({"_id": ObjectId(id)},
            {$set:{log:oldFin}},
            function(err) {
              // Deleting goal
              gmodels.Goal.remove({"_id": ObjectId(id)},
                function(err, result) {
                  if (!err) {
                    models.User.findOne({name: senderID},
                    function(err, result) {
                      models.User.update({name:senderID},
                      {$set:{numGoals:result.numGoals - 1}},
                      function(err) {
                        sendTextMessage(senderID, "CONGRATS on finishing your goal: " +
                                                  goal.name +
                                                  "! You did an absolutely fantastic job. :)" +
                                                  "Your goal has been moved to the finished section View Goals. Going to home...");
                        sendHome(senderID);
                      });
                    });
                  }
                  else {
                    sendTextMessage(senderID, "There was an error finishing your goal, please try again, going to home...")
                    sendHome(senderID);
                  }
                });
            });
        });
      });


    } else if (payload == "home") {
      sendHome(senderID);
    }
    return;
  }

  // Message Texts
  if (messageText) {
      messageText = messageText.toLowerCase();

      // Check status
      models.User.findOne({name: senderID},
        function(err, result) {
          if (result != null) {
            // Statuses
            if (result.status == 'naming_goal') {
              nameGoal(senderID, messageText)
            } else if (result.status.substring(0,12) == 'logging_goal') {
              console.log(result.status.substring(12,result.status.length))
              logGoal(senderID,
                      result.status.substring(12,result.status.length),
                      messageText);
            }
            if (result.status == 'null') {
              // Standard cases
              switch (messageText) {
                case 'image':
                  sendImageMessage(senderID);
                  break;
                case 'generic':
                  sendGenericMessage(senderID);
                  break;
                case 'test':
                  sendTest(senderID);
                  break;
                default:
                  console.log("sending home")
                  sendHome(senderID);
              }
            }
          }
        });

    // Check commands
    // if (messageText.includes("start")) {
    //   makeGoal(senderID);
    //   return;
    // } else if (messageText.includes("add")) {
    //   models.User.update({name:senderID},
    //     {$set:{status:'logging_goal'}},
    //     function(err) {
    //       sendTextMessage(senderID, "Add a log message for your goal!");
    //     });
    //   return;
    // }
  } else {
    sendHome(senderID);
  }
}

// Bot Logic Functions

// New Goal Functions:
function makeGoal(senderID) {
  models.User.findOne({name: senderID},
  function(err, result) {
    if (result.numGoals == 5) {
      sendTextMessage(senderID, 'You have reached the maximum number of goals. Finish one or delete one to add more! Going to home...');
      sendHome(senderID);
    } else {
      models.User.update({name:senderID},
      {$set:{status:'naming_goal'}},
      function(err) {
        sendTextMessage(senderID, "What is the name of your goal?");
      });
    }
  });
}

function nameGoal(senderID, messageText) {
  messageText = messageText.charAt(0).toUpperCase() + messageText.slice(1);
  if (messageText.length > 100) {
    sendTextMessage(senderID, "That goal name is too long. Try another name.")
    return;
  }
  gmodels.Goal.findOne({user:senderID, name:messageText}, function(err, result) {
    var d = new Date();
    // Find if there already exists a goal
    if (result != null) {
      sendTextMessage(senderID, "Goal with that name has already been created. Try another name.")
      return;
    } else {
      // Create Goal
      var newGoal = new gmodels.Goal({
        user: senderID,
        name: messageText,
        streak: 0,
        log: [],
        lastUpdate: d.getTime() / 1000,
        lastDay: d.getDay(),
        total: 0
      });
      newGoal.save(function() {
        console.log("new goal created");
        models.User.update({name:senderID},
          {$set:{status:'null'}},
          function(err) {
            sendTextMessage(senderID, "Goal " + messageText + " Added. Be sure to add progress to it every day to build up your goal streak! Going to home...");
            sendHome(senderID);
        });
      });
    }
  });
  // Update Goal Count
  models.User.findOne({name: senderID},
  function(err, result) {
    models.User.update({name:senderID},
    {$set:{numGoals:result.numGoals + 1}},
    function(err) {
      sendTextMessage(senderID, "What is the name of your goal?");
    });
  });
}

// View Goal / Add Prog Functions:
function getList(senderID, type) {
  // Create new user or identify user
  gmodels.Goal.find({user:{$in:[senderID]}}, function(err, result) {
    if (result == null || result.length == 0) {
      sendTextMessage(senderID, "No goals yet, start one from home!");
      sendHome(senderID);
      console.log("empty");
    } else {
      // Update streaks
      for (var i = 0; i < result.length; i++) {
        console.log("processing streak")
        streakProcess(result[i]._id, "view", senderID)
      }
      // send list again
      setTimeout(function(){
        gmodels.Goal.find({user:{$in:[senderID]}}, function(err, result) {
          if (result == null || result.length == 0) {
            sendTextMessage(senderID, "No goals yet, start one from home!");
            sendHome(senderID);
            console.log("empty");
          } else {
            sendList(senderID, result, type);
          }
        });
      }, 1500);

    }
  });
}

// Sending the first list
function sendList(senderID, result, type) {
  // console.log('results');
  // console.log(result);
  var message = "Here are your goals:\u000A";
  var quick = [];
  for (var i = 0; i < result.length; i++) {
    message += String(i+1) + ". " + result[i].name;
    // if (result[i].streak >= 3) {
    //   message += "  🔥" + String(result[i].streak);
    // }
    message += "  🔥" + String(result[i].streak);
    message +=  "\u000A";
    quick.push({
      "content_type":"text",
      "title":result[i].name,
      "payload": type + " " + result[i]._id
    });
  }
    // Check if finished goal and add
  models.User.findOne({name:senderID}, function(err, result) {
    if (type == "view") {
      message += "Tap on a goal below to view more details.";
      if (result.finished.length != 0) {
        quick.push({
          "content_type":"text",
          "title":"Finished Goals",
          "payload": "Payload finished"
        });
      }
    } else if (type =="prog") {
      message += "Tap on a goal below to add progress to it!"
    }
    var messageData = {
      recipient: {
        id: senderID
      },
      message: {
        text: message,
        quick_replies: quick
      }
    };
    callSendAPI(messageData);
  });
}

// Sending the individual goal to view
function sendGoal(senderID, goal) {
  var message = goal.name;
  // if (goal.streak >= 3) {
  //   message += "  🔥" + String(goal.streak);
  // }
  message += "  🔥" + String(goal.streak);
  var messageData = {
    recipient: {
      id: senderID
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [
            {
              title: message,
              buttons: [
                {
                  type: "postback",
                  title: "View Logs",
                  payload: "logs " + goal._id,
                }, {
                  type: "postback",
                  title: "Finish Goal",
                  payload: "finish " + goal._id,
                }, {
                  type: "postback",
                  title: "Delete Goal",
                  payload: "dele " + goal._id,
                }
              ]
            }
          ]
        }
      }
    }
  };
  callSendAPI(messageData);
}
// Streak processing
function streakProcess(id, type, senderID) {
  var d = new Date();
  if (type == "prog") {
    var inc = 1;
  } else {
    var inc = 0;
  }
  gmodels.Goal.findOne({"_id": ObjectId(id)},
    function(err, result) {
      var res = streak(senderID, result, id);
      if (res == "add") {
        console.log("add")
        console.log(inc)
        var newStreak = result.streak + inc;
      } else if (res == "keep") {
        console.log("keep")
        var newStreak = Math.max(inc, result.streak);
      } else {
        var newStreak = inc;
      }
      var total = result.total + inc
      if (res=="reset") {
        gmodels.Goal.update({"_id": ObjectId(id)},
        {$set:{streak:newStreak}},
        function(err) {
          console.log("set", newStreak)
          return;
        });
      }
      if (type == "prog") {
        gmodels.Goal.update({"_id": ObjectId(id)},
        {$set:{streak:newStreak,
               lastUpdate:d.getTime(),
               lastDay:d.getDay(),
               total:total}},
        function(err) {
          return;
        });
      }
    });
}
// Adding progress to the individual goal
function streak(senderID, goal) {
  var d = new Date();
  // Streak updating
  var time = d.getTime();
  var day = d.getDay();
  var diffDay = day - goal.lastDay;
  var diffTime = (time - goal.lastUpdate)/1000;

  // Different date, less than 48 hrs
  if ((diffDay  == 1 ||  diffDay == -6) && diffTime < 86400 * 2) {
    // Add to streak
    return "add";
  } else if (diffDay == 0) {
    console.log(time, "time")
    console.log(diffTime, "diffTime")
    console.log(diffDay, "diffDay")
    console.log(day, "day")
    console.log(goal.lastDay, "goal last day")
    return "keep";
  }
  // Set to streak to 0
  console.log("reset")
  return "reset";
}

// Adding a goal log
function logGoal(senderID, id, text) {
  if (text.length > 96) {
    sendTextMessage(senderID, "That goal log is too long. Try another log.");
    return;
  }
  var d = new Date();
  gmodels.Goal.findOne({"_id": ObjectId(id)},
  function(err, result) {
    var oldLog = result.log;
    oldLog.unshift(String(d.getMonth()) + '/' + d.getDate() + ' ' + text)
    gmodels.Goal.update({"_id": ObjectId(id)},
      {$set:{log:oldLog}},
      function(err) {
        models.User.update({name:senderID},
          {$set:{status:'null'}},
          function(err) {
            sendTextMessage(senderID, "Log Added! Great job today! Here's your daily dose of motivation from /r/GetMotivated:");
            sendMotivation(senderID);
            // send motivation here
            // sendHome(senderID);
        });
        return;
      });
  });
  return true;
}

// Send motivation after user adds progress
function sendMotivation(senderID) {
  models.User.findOne({name:senderID}, function(err, result) {
    var dataR;
    var images = [];
    var index = result.lastPicTime;
    // Get reddit data
    reddit.r('GetMotivated', function(err, data, res){
      dataR = data.data.children; //outputs object representing first page of GM subreddit
      for (var i = 0; i < dataR.length; i++) {
        if (dataR[i].data.link_flair_css_class == 'image' &&
            dataR[i].data.score >= 50) {
          images.push(dataR[i].data);
        }
      }
      // Check if length of 0
      if (images.length == 0) {
        console.log("none");
        sendHome(senderID);
        return;
      }
      index = index % images.length;
      // sort by created time
      images.sort(function(a,b) {
        return parseFloat(a.created_utc - b.created_utc);
      });
      // update last time
      console.log(images[index].url);
      // var preurl = images[index].url;
      // preurl = preurl.replace(".gifv", ".gif")
      // console.log(preurl)
      while (images[index].url.includes("imgur") &&
             (!images[index].url.includes("png") ||
              !images[index].url.includes("jpg") ||
              !images[index].url.includes("jpeg"))) {
        index += 1;
        index = index % images.length;
      }
      var name = images[index].title;
      sendTextMessage(senderID, name.substring(7,name.length));
      models.User.update({name:senderID},
      {$set:{lastPicTime:index + 1}},
      function(err) {
        try {
          sendImageMessage(senderID, images[index].url);
        }
        catch(e) {
          sendTextMessage(senderID, images[index].url)
        }
      });
    });
  });
}

// View goal logs
function viewLogs(senderID, goal, index) {
  var message = "Here are your logs for " + goal.name +
                " (Page " + (index/5 + 1) + ")\u000A";
  // console.log(goal.log, "1")
  // var logs = goal.log.reverse()
  // console.log(goal.log, "2")
  // console.log(logs, "3")
  for (var i = index; i < Math.min(goal.log.length, index + 5); i++) {
      message += goal.log[i];
      message +=  "\u000A";
  }
  var quickReply = [
          {
            "content_type":"text",
            "title":"Home",
            "payload":"home"
          }];

  if (index + 5 < goal.log.length) {
      quickReply.unshift(
          {
            "content_type":"text",
            "title":"View Next Logs",
            "payload":"logs" + String(index + 5) + "!" + goal._id
          });
  }
  if (index - 5 >= 0) {
      quickReply.unshift(
          {
            "content_type":"text",
            "title":"View Previous Logs",
            "payload":"logs" + String(index - 5) + "!" + goal._id
          });
  }

  var messageData = {
      recipient: {
        id: senderID
      },
      message: {
        text:message,
        quick_replies: quickReply
      }
  };
  callSendAPI(messageData);
}

function sendConfirm(senderID, id) {
  gmodels.Goal.findOne({"_id": ObjectId(id)},
  function(err, result) {
    var messageData = {
      recipient: {
        id: senderID
      },
      message: {
        text: "Are you sure you want to delete " + result.name + "? This cannot be undone.",
        quick_replies: [
          {
            "content_type":"text",
            "title":"Yes",
            "payload":"yes  " + id
          },
          {
            "content_type":"text",
            "title":"No",
            "payload":"no   " + id
          }
        ]
      }
    };
    callSendAPI(messageData);
  });

}

function sendConfirmFinish(senderID, id) {
  gmodels.Goal.findOne({"_id": ObjectId(id)},
  function(err, result) {
    var messageData = {
      recipient: {
        id: senderID
      },
      message: {
        text: "Are you sure you want to finish " +
          result.name +
          "? This cannot be undone. Finishing a goal will stop you from adding it, but it will be saved in your finished section forever",
        quick_replies: [
          {
            "content_type":"text",
            "title":"Yes",
            "payload":"yef  " + id
          },
          {
            "content_type":"text",
            "title":"No",
            "payload":"nf   " + id
          }
        ]
      }
    };
    callSendAPI(messageData);
  });

}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  if (payload == "Payload new goal") {
    makeGoal(senderID);
  } else if (payload == "Payload view") {
    getList(senderID, "view");
  } else if (payload == "Payload progress") {
    getList(senderID, "prog");
  } else if (payload.substring(0,4) == "logs") {
      var id = payload.substring(5,payload.length);
      gmodels.Goal.findOne({"_id": ObjectId(id)},
        function(err, result) {
          console.log(result);
          viewLogs(senderID, result, 0);
        });
  } else if (payload.substring(0,4) == "dele") {
      var id = payload.substring(5,payload.length);
      sendConfirm(senderID, id);
  } else if (payload.substring(0,6) == "finish") {
      var id = payload.substring(7,payload.length);
      sendConfirmFinish(senderID, id);
  } else if (payload == "Payload start") {
    sendTextMessage(senderID, "Welcome to Goalt, your own goal tracker. Click on New Goal to start. Continue to add progress to achieve your goals!");
    setTimeout(function(){ sendHome(senderID) }, 1500);
  } else if (payload == "Payload finished") {

    models.User.findOne({name:senderID}, function(err, result) {
      var message = "Here are your finished goals:\u000A";
      var rev = result.finished.reverse()
      for (var i = 0; i < result.length; i++) {
        message += String(i+1) + ". " + rev[i];
        message +=  "\u000A";
      }
      sendHomeMessage(senderID, message);
    })
  }

}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

// Send Home

function sendHome(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [
            {
              title: "GoalT: A Goal Tracker For You",
              subtitle: "Type anything or press 👍 to return Home",
              image_url: SERVER_URL + "/assets/home.png",
              buttons: [
                {
                  type: "postback",
                  title: "New Goal",
                  payload: "Payload new goal",
                }, {
                  type: "postback",
                  title: "View Goals",
                  payload: "Payload view",
                }, {
                  type: "postback",
                  title: "Add Progress",
                  payload: "Payload progress",
                }
              ]
            }
          ]
        }
      }
    }
  };
  callSendAPI(messageData);
}

function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}
/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

function sendHomeMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Home",
          "payload":"home"
        }
      ]

    }
  };
  callSendAPI(messageData);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId, image_url) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: image_url
        }
      },
      quick_replies: [
        {
          "content_type":"text",
          "title":"Home",
          "payload":"home"
        }
      ]
    }
  };
  try {
    callSendAPI(messageData);
  }
  catch(e) {
    sendTextMessage(recipientId, image_url);
  }
}

function sendTest(senderID) {
  var url = 'https://graph.facebook.com/v2.6/' + senderID + '?access_token=' + PAGE_ACCESS_TOKEN;
  var options = {
    url: url,
    json: true
  };
  request.get(options, function(error, response, body) {
    if (!error && response.statusCode === 200) {
      console.log("devices:");
      console.log(body);
      // sendTextMessage(senderID, "Hi " + body.first_name + ", I am Anna the fashion bot. I can help you buy anything you see. Send me an image or message! :)");
      var messageData = {
        recipient: {
          id: senderID
        },
        message: {
          text:"hi " + body.first_name,
          quick_replies: [
            {
              "content_type":"text",
              "title":"Image Search",
              "payload":"imageSearch"
            },
            {
              "content_type":"text",
              "title":"Text Search",
              "payload":"textSearch"
            },
            {
              "content_type":"text",
              "title":"Today's Sales",
              "payload":"sale"
            }
          ]
        }
      };
      callSendAPI(messageData);
    } else {
      console.log('user api error');
    }
  });

}


/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      sendHome(recipientId);
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

