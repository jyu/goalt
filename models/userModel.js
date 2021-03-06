var mongoose = require('mongoose');

// Define a schema: this gives us a structure for our data
var userSchema = mongoose.Schema({
  name: Number,
  status: String,
  numGoals: Number,
  finished: [String],
  lastPicTime: Number
});

// For more complex logic, methods go here
// e.g. userSchema.methods.methodName = function()...
// or userSchema.statics.methodName = function()...

// We compile the schema into a model, which is actually a class we can do things on.
var User = mongoose.model('User', userSchema);

var checkLength = function(s) {
  return s.length > 0;
};

// Validators for our model. When we save or modify our model, these validators
// get run. If they return false, an error happens.

exports.User = User;
