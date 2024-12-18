require("dotenv").config();
const UserModel = require("../Models/UserModel");
const jwt = require("jsonwebtoken");
const maxAge = 3 * 24 * 60 * 60;
const Notification = require("../Models/NotificationModel");

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: maxAge,
  });
};

const handleErrors = (err) => {
  let errors = { phoneNumber: "", password: "" };
  if (err.message === "incorrect phone number") {
    errors.phoneNumber = "Phone number is not registered";
  }
  if (err.message === "incorrect password") {
    errors.password = "Password is incorrect";
  }
  if (err.code === 11000) {
    errors.phoneNumber = "Phone number is already registered";
    return errors;
  }
  if (err.message.includes("Users validation failed")) {
    Object.values(err.errors).forEach(({ properties }) => {
      errors[properties.path] = properties.message;
    });
  }
  return errors;
};

module.exports.register = async (req, res, next) => {
  try {
    const { firstName, lastName, phoneNumber, password } = req.body;
    const username = phoneNumber; // Using phone number as a unique identifier for username

    // Create a new user with assignedAgent set to null
    const user = await UserModel.create({
      firstName,
      lastName,
      phoneNumber,
      password,
      username,
      assignedAgent: null, // Default to null (no agent assigned)
    });

    // Create token
    const token = createToken(user._id);

    // Create a notification for super admin and admin
    const adminNotificationText = `A new account has been created`;
    const adminNotification = new Notification({
      type: "account creation",
      notification: adminNotificationText,
    });

    // Save the notification
    await adminNotification.save();

    // Find all super admins and admins
    const adminUsers = await UserModel.find({
      role: { $in: ["super admin", "admin"] },
    });

    // Add the notification to all super admins and admins
    await Promise.all(
      adminUsers.map(async (adminUser) => {
        adminUser.notifications.push(adminNotification._id);
        await adminUser.save();
      })
    );

    // Create a notification for the newly created user
    const userNotificationText = `Your account is being approved.`;
    const userNotification = new Notification({
      type: "account creation",
      notification: userNotificationText,
    });

    // Save the notification
    await userNotification.save();

    // Add the notification to the new user
    user.notifications.push(userNotification._id);
    await user.save();

    // Send the response with the created user and token
    res.cookie("jwt", token, {
      withCredentials: true,
      httpOnly: false,
      maxAge: maxAge * 1000,
      sameSite: "none",
      secure: true,
    });

    res.status(201).json({
      user: user._id,
      firstName: user.firstName,
      username: user.username,
      created: true,
      jwt: token,
    });
  } catch (err) {
    console.log(err);
    const errors = handleErrors(err); // Handle errors if any
    res.json({ errors, created: false });
  }
};

module.exports.login = async (req, res, next) => {
  const { phoneNumber, password } = req.body;
  try {
    const user = await UserModel.login(phoneNumber, password);

    const token = createToken(user._id);

    res.cookie("jwt", token, {
      httpOnly: false,
      maxAge: maxAge * 1000,
      sameSite: "none",
      secure: true,
    });

    res.status(200).json({
      user: user._id,
      firstName: user.firstName,
      username: user.username,
      status: true,
      jwt: token,
    });
  } catch (err) {
    console.log(err);
    const errors = handleErrors(err);
    res.json({ errors, status: false });
  }
};
