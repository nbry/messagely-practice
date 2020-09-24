/** User class for message.ly */

const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const db = require("../db");
const jwt = require("jsonwebtoken");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    try {
      // hashed password
      const hashedPass = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

      // save to db
      const results = await db.query(
        `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, now(), current_timestamp)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPass, first_name, last_name, phone]
      );
      const user = results.rows[0];
      return user;
    } catch (e) {
      if (e.code === "23505") {
        throw new ExpressError("Username taken. Please pick another", 400);
      }
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */
  static async authenticate(username, password) {
    // if username or password empty...
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }

    // find user
    const results = await db.query(
      `SELECT username, password
        FROM users
        WHERE username = $1`,
      [username]
    );

    // authenticate and return boolean
    const user = results.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username }, SECRET_KEY);
        return true;
      }
    }
    return false;
  }

  /** Update last_login_at for user */
  static async updateLoginTimestamp(username) {
    await db.query(
      `UPDATE users
      SET last_login_at = current_timestamp
      WHERE username = $1`,
      [username]
    );
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */
  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    const users = results.rows;
    return users;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */
  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at 
      FROM users 
      WHERE username = $1`,
      [username]
    );
    const user = results.rows[0];
    if (!user) {
      throw new ExpressError("user not found", 404);
    }
    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT m.id, m.to_username, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone 
      FROM messages AS m
      LEFT JOIN users AS u 
      ON m.to_username = u.username
      WHERE m.from_username = $1`,
      [username]
    );
    const messages = results.rows.map((r) => {
      return {
        id: r.id,
        to_user: {
          username: r.to_username,
          first_name: r.first_name,
          last_name: r.last_name,
          phone: r.phone,
        },
        body: r.body,
        sent_at: r.sent_at,
        read_at: r.read_at,
      };
    });
    console.log(messages);

    if (!messages) {
      throw new ExpressError("messages not found", 404);
    }
    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */
  static async messagesTo(username) {
    const results = await db.query(
      `SELECT m.id, m.to_username, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone 
      FROM messages AS m
      LEFT JOIN users AS u 
      ON m.from_username = u.username
      WHERE m.to_username = $1`,
      [username]
    );
    const messages = results.rows.map((r) => {
      return {
        id: r.id,
        from_user: {
          username: r.username,
          first_name: r.first_name,
          last_name: r.last_name,
          phone: r.phone,
        },
        body: r.body,
        sent_at: r.sent_at,
        read_at: r.read_at,
      };
    });
    if (!messages) {
      throw new ExpressError("messages not found", 404);
    }
    return messages;
  }
}

module.exports = User;
