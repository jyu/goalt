var mongoose = require('mongoose');

var goalSchema = mongoose.Schema({
  user: Number,
  name: String,
  streak: Number,
  log: [String],
  lastUpdate: Number,
  longestStreak: Number,
});

var Goal = mongoose.model('Goal', goalSchema);

exports.Goal = Goal;
