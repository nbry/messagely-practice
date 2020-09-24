const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");

const Message = require("../models/message");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    const message = await Message.get(id);
    if (
      req.user.username == message.from_user.username ||
      req.user.username == message.to_user.username
    ) {
      return res.json(message);
    } else {
      throw new ExpressError("Not Authorized", 401);
    }
  } catch (e) {
    return next(e);
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post("/", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.create({
      from_username: req.user.username,
      to_username: req.body.to_username,
      body: req.body.body,
    });

    return res.json(message);
  } catch (e) {
    return next(e);
  }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post("/:id/read", async (req, res, next) => {
  try {
    const id = req.params.id;
    const message = await Message.get(id);
    if (req.user.username == message.to_user.username) {
      const results = await Message.markRead(id);
      return res.json(results);
    } else {
      throw new ExpressError("Not Authorized", 401);
    }
  } catch (e) {
    return next(e);
  }
});
module.exports = router;
