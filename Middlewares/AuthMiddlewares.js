require("dotenv").config();
const jwt = require("jsonwebtoken");
const User = require("../Models/UserModel");
const Submission = require("../Models/SubmissionModel");
const AccountDetails = require("../Models/AccountDetailsModel");
const Notification = require("../Models/NotificationModel");
const ButtonLinksModel = require("../Models/ButtonLinksModel");

module.exports.checkUser = (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        res.json({ status: false });
        next();
      } else {
        const user = await User.findById(decodedToken.id);
        const populatedUser = await User.findOne({
          _id: decodedToken.id,
        });

        if (user)
          res.json({
            status: true,
            phoneNumber: user.phoneNumber,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            accountStatus: user.accountStatus,
          });
        else res.json({ status: false });
        next();
      }
    });
  } else {
    res.json({ status: false });
    next();
  }
};

module.exports.deposit = async (req, res, next) => {
  try {
    const { paymentMethod, amount } = req.body;
    let file = "";

    if (req.file) {
      file = req.file.filename;
    }

    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({ status: false, message: "Unauthorized." });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Invalid token." });
      }

      const user = await User.findById(decodedToken.id);
      const userId = decodedToken.id;

      if (!paymentMethod || !amount || !file) {
        return res.status(400).json({
          error: "Payment method, amount, and screenshot are required.",
        });
      }

      // Create a new deposit submission
      const newSubmission = new Submission({
        user: userId,
        type: "deposit",
        username: user.username,
        phoneNumber: user.phoneNumber,
        amount,
        paymentMethod,
        file,
      });

      // Save the deposit submission
      await newSubmission.save();

      // Create a notification for the deposit action
      const depositNotificationText = `${user.username} did a deposit. Check their submission.`;
      const depositNotification = new Notification({
        type: "deposit",
        notification: depositNotificationText,
      });

      // Save the notification
      await depositNotification.save();

      // Notify assigned agent and admin (if any)
      if (user.assignedAgent) {
        const assignedAgent = await User.findById(user.assignedAgent);

        if (assignedAgent) {
          // Add notification to assigned agent's notifications
          assignedAgent.notifications.push(depositNotification._id);
          await assignedAgent.save();

          if (assignedAgent.assignedAgent) {
            const assignedAdmin = await User.findById(
              assignedAgent.assignedAgent
            );
            if (assignedAdmin) {
              // Add notification to assigned admin's notifications
              assignedAdmin.notifications.push(depositNotification._id);
              await assignedAdmin.save();
            }
          }
        }
      }

      // Notify all super admins
      const superAdmins = await User.find({ role: "super admin" });
      await Promise.all(
        superAdmins.map(async (superAdmin) => {
          superAdmin.notifications.push(depositNotification._id);
          await superAdmin.save();
        })
      );

      // Add submission to the user's submissions array
      user.submissions.push(newSubmission._id);
      await user.save();

      res.status(201).json({
        message: "Deposit submission created successfully.",
        submission: newSubmission,
        notification: depositNotification,
      });
    });
  } catch (error) {
    console.error("Error creating deposit submission:", error);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.withdraw = async (req, res, next) => {
  try {
    const { paymentGateway, bankName, accountName, accountNumber, amount } =
      req.body;

    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Invalid token." });
      }

      const user = await User.findById(decodedToken.id);
      const userId = decodedToken.id;

      if (!paymentGateway || !amount || !accountName || !accountNumber) {
        return res.status(400).json({
          error:
            "Payment gateway, account name, account number, and amount are required.",
        });
      }

      // Create a new withdrawal submission
      const newSubmission = new Submission({
        user: userId,
        type: "withdrawal",
        username: user.username,
        phoneNumber: user.phoneNumber, // Use phoneNumber field
        amount,
        paymentGateway,
        bankName,
        accountName,
        accountNumber,
      });

      // Save the submission
      const savedSubmission = await newSubmission.save();

      // Create a notification for the withdrawal request
      const withdrawalNotificationText = `${user.username} requests a withdrawal.`;
      const withdrawalNotification = new Notification({
        type: "withdraw",
        notification: withdrawalNotificationText,
      });

      // Save the notification
      await withdrawalNotification.save();

      // Notify the assigned agent and their assigned admin (if any)
      if (user.assignedAgent) {
        const assignedAgent = await User.findById(user.assignedAgent);

        if (assignedAgent) {
          // Add notification to assigned agent's notifications
          assignedAgent.notifications.push(withdrawalNotification._id);
          await assignedAgent.save();

          if (assignedAgent.assignedAgent) {
            const assignedAdmin = await User.findById(
              assignedAgent.assignedAgent
            );
            if (assignedAdmin) {
              // Add notification to assigned admin's notifications
              assignedAdmin.notifications.push(withdrawalNotification._id);
              await assignedAdmin.save();
            }
          }
        }
      }

      // Notify all super admins
      const superAdmins = await User.find({ role: "super admin" });
      await Promise.all(
        superAdmins.map(async (superAdmin) => {
          superAdmin.notifications.push(withdrawalNotification._id);
          await superAdmin.save();
        })
      );

      // Add submission to the user's submissions array
      user.submissions.push(savedSubmission._id);
      await user.save();

      res.status(201).json({
        message: "Withdrawal submission created successfully.",
        submission: savedSubmission,
        notification: withdrawalNotification,
      });
    });
  } catch (error) {
    console.error("Error creating withdrawal submission:", error);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.submissions = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    try {
      // Decode the JWT token to get the logged-in user details
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const loggedInUser = await User.findById(decoded.id); // Use decoded.id for user ID

      // Fetch all submissions and populate the user field
      const submissions = await Submission.find().populate("user");

      if (loggedInUser.role === "super admin") {
        // Super admin can see all submissions
        return res.json(submissions);
      }

      if (loggedInUser.role === "admin") {
        // Admin can see submissions assigned to them directly
        const filteredSubmissions = submissions.filter((submission) => {
          const userAssignedAgent = submission.user?.assignedAgent?.toString();
          return userAssignedAgent === loggedInUser._id.toString();
        });

        return res.json(filteredSubmissions);
      }

      if (loggedInUser.role === "agent") {
        // Agent can see submissions assigned to them directly
        const filteredSubmissions = submissions.filter((submission) => {
          const userAssignedAgent = submission.user?.assignedAgent?.toString();
          return userAssignedAgent === loggedInUser._id.toString();
        });

        return res.json(filteredSubmissions);
      }

      // If the user has an unrecognized role
      return res.status(403).json({
        message: "You are not authorized to view these submissions.",
      });
    } catch (err) {
      console.error("Error processing submissions:", err);
      return res.status(500).json({ message: "Error fetching submissions." });
    }
  } catch (err) {
    console.error("Error in submissions route:", err);
    return res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.updateSubmission = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Invalid token." });
      }

      const { id } = req.params;
      const { status, declineReason } = req.body;

      // Validate status
      if (!["pending", "approved", "declined"].includes(status)) {
        return res.status(400).json({ message: "Invalid status value" });
      }

      try {
        const submission = await Submission.findById(id);

        if (!submission) {
          return res.status(404).json({ message: "Submission not found" });
        }

        // Update submission status
        submission.status = status;
        if (status === "declined" && declineReason) {
          submission.declineReason = declineReason; // Optional: Add reason for decline
        }
        await submission.save();

        // Create notification for the user
        let notificationText;
        if (status === "approved") {
          notificationText = `Your submission (ID: ${submission._id}) has been approved.`;
        } else if (status === "declined") {
          notificationText = `Your submission (ID: ${
            submission._id
          }) has been declined. ${
            declineReason ? `Reason: ${declineReason}` : ""
          }`;
        }
        if (status !== "pending") {
          const notification = new Notification({
            type: "submission update",
            notification: notificationText,
          });

          await notification.save();
          const user = await User.findById(submission.user);

          if (user) {
            // Add notification to the user's notifications array
            user.notifications.push(notification._id);
            await user.save();
          }
        }

        res.json({
          message: "Submission status updated successfully",
          submission,
        });
      } catch (error) {
        console.error("Error updating submission status:", error);
        res.status(500).json({ message: "Error updating submission status" });
      }
    });
  } catch (error) {
    console.error("Error updating submission:", error);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.deleteSubmission = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    const { id } = req.params;

    try {
      // Find the submission by ID
      const submission = await Submission.findById(id).populate("user");

      if (!submission) {
        return res.status(404).json({ message: "Submission not found" });
      }

      const user = submission.user;

      // Delete the submission
      await Submission.findByIdAndDelete(id);

      // Notify the user about the deletion
      const notificationMessage = `Your submission (ID: ${submission._id}) has been deleted.`;
      const newNotification = new Notification({
        type: "submission deleted",
        notification: notificationMessage,
      });

      // Save the notification
      await newNotification.save();

      // Add the notification to the user's notifications array
      user.notifications.push(newNotification._id);
      await user.save();

      // Respond with success message
      res.json({
        message: "Submission deleted successfully, and user notified.",
      });
    } catch (err) {
      console.error("Error deleting submission:", err);
      res.status(500).json({ message: "Error deleting submission" });
    }
  } catch (err) {
    console.error("Error in deleteSubmission route:", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.getAccountDetails = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      const accountDetails = await AccountDetails.findOne();
      if (!accountDetails) {
        return res.status(404).json({ message: "Account details not found" });
      }
      res.json(accountDetails);
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Deleting Submission", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.updateAccountDetails = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      const {
        bankName,
        bankAccountName,
        bankAccountNumber,
        easypaisaAccountName,
        easypaisaAccountNumber,
        jazzcashAccountName,
        jazzcashAccountNumber,
      } = req.body;

      // Find the single document or create one if it doesn't exist
      const accountDetails = await AccountDetails.findOneAndUpdate(
        {},
        {
          bankName,
          bankAccountName,
          bankAccountNumber,
          easypaisaAccountName,
          easypaisaAccountNumber,
          jazzcashAccountName,
          jazzcashAccountNumber,
        },
        { new: true, upsert: true }
      );

      res.json(accountDetails);
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Deleting Submission", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.getUsers = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    try {
      // Verify the token and extract user info
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decodedToken.id;

      // Fetch the logged-in user's details to check their role
      const loggedInUser = await User.findById(userId).select(
        "role assignedAgent"
      );
      if (!loggedInUser) {
        return res.status(404).json({ message: "User not found" });
      }

      let users;

      // If the logged-in user is a "user", deny access
      if (loggedInUser.role === "user") {
        return res.status(403).json({ message: "Access denied" });
      }

      // If the logged-in user is an "agent", send only the users assigned to them
      if (loggedInUser.role === "agent") {
        users = await User.find({ assignedAgent: userId }).populate(
          "assignedAgent",
          "firstName lastName username role"
        );
      }

      // If the logged-in user is an "admin", send agents assigned to them and users assigned to those agents
      else if (loggedInUser.role === "admin") {
        users = await User.find({
          $or: [
            { assignedAgent: userId }, // Find users directly assigned to this admin
            {
              assignedAgent: {
                $in: await User.find({ assignedAgent: userId }).distinct("_id"),
              },
            }, // Find users assigned to agents under this admin
          ],
        }).populate("assignedAgent", "firstName lastName username role");
      }

      // If the logged-in user is a "super admin", send all users
      else if (loggedInUser.role === "super admin") {
        users = await User.find().populate(
          "assignedAgent",
          "firstName lastName username role"
        );
      }

      // Send the list of users based on the role
      res.json(users);
    } catch (err) {
      console.error("Error fetching users:", err);
      res.status(500).json({ message: "Internal server error." });
    }
  } catch (err) {
    console.error("Error verifying token:", err);
    res.status(500).json({ message: "Internal server error." });
  }
};

module.exports.deleteUsers = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      try {
        // Find the user to be deleted by username
        const user = await User.findOne({ username: req.params.username });

        // If user not found, return an error
        if (!user) return res.status(404).json({ message: "User not found" });

        // Prevent deletion of users with 'super admin' role
        if (user.role === "super admin") {
          return res
            .status(400)
            .json({ message: "Cannot delete super admin user" });
        }

        // Proceed with deletion if not a super admin
        await User.findOneAndDelete({ username: req.params.username });

        // Return success message after deletion
        res.json({ message: "User deleted successfully" });
      } catch (err) {
        res.status(500).json({ message: err.message });
      }
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Deleting User", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.depositHistory = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
        try {
          const { username } = req.params;

          // Find all submissions of type 'deposit' for the current user
          const deposits = await Submission.find({
            user: decodedToken.id,
            type: "deposit",
          }).sort({ createdAt: -1 });

          res.json(deposits);
        } catch (error) {
          console.error("Error fetching deposit history:", error);
          res.status(500).json({ error: "Internal Server Error" });
        }
      });
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Deleting Submission", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.withdrawHistory = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
        if (err) {
          return res
            .status(401)
            .json({ status: false, message: "Unauthorized access" });
        }

        try {
          const { username } = req.params;

          // Find all submissions of type 'withdrawal' for the current user
          const withdrawals = await Submission.find({
            user: decodedToken.id,
            type: "withdrawal",
          }).sort({ createdAt: -1 });

          res.json(withdrawals);
        } catch (error) {
          console.error("Error fetching withdrawal history:", error);
          res.status(500).json({ error: "Internal Server Error" });
        }
      });
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
    }
  } catch (err) {
    console.error("Error fetching withdrawal history", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.updateUser = async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Unauthorized access" });
      }

      const requestingUser = await User.findById(decodedToken.id);
      if (!requestingUser) {
        return res
          .status(404)
          .json({ status: false, message: "Requesting user not found" });
      }

      const { username } = req.params;
      const { firstName, lastName, role, accountStatus, assignedAgent } =
        req.body;

      // Find the target user
      const targetUser = await User.findOne({ username });
      if (!targetUser) {
        return res
          .status(404)
          .json({ status: false, message: "Target user not found" });
      }

      // Handle super admin role restrictions
      if (
        targetUser.role === "super admin" &&
        requestingUser.role !== "super admin"
      ) {
        return res.status(403).json({
          status: false,
          message: "Only super admins can update super admin users",
        });
      }

      // Verify assignedAgent if provided
      if (assignedAgent) {
        const agent = await User.findById(assignedAgent);
        if (!agent) {
          return res
            .status(400)
            .json({ status: false, message: "Invalid assigned agent ID" });
        }

        if (role === "user" && agent.role !== "agent") {
          return res.status(400).json({
            status: false,
            message: "Users can only be assigned to agents",
          });
        }

        if (role === "agent" && agent.role !== "admin") {
          return res.status(400).json({
            status: false,
            message: "Agents can only be assigned to admins",
          });
        }
      }

      // Capture original role and account status
      const originalRole = targetUser.role;
      const originalStatus = targetUser.accountStatus;

      // Update the user
      const updatedUser = await User.findOneAndUpdate(
        { username },
        { firstName, lastName, role, accountStatus, assignedAgent },
        { new: true, runValidators: true }
      );

      if (!updatedUser) {
        return res
          .status(404)
          .json({ status: false, message: "User not found" });
      }

      // Send notifications if role or status changes
      if (role && role !== originalRole) {
        const roleChangeNotification = new Notification({
          type: "role change",
          notification: `Your role has been updated to ${role}`,
        });
        await roleChangeNotification.save();

        updatedUser.notifications.push(roleChangeNotification._id);
      }

      if (accountStatus === "approved" && accountStatus !== originalStatus) {
        const statusApprovalNotification = new Notification({
          type: "account approval",
          notification: "Your account has been approved",
        });
        await statusApprovalNotification.save();

        updatedUser.notifications.push(statusApprovalNotification._id);
      }

      // Save the updated user with new notifications
      await updatedUser.save();

      res.status(200).json({
        status: true,
        message: "User updated successfully",
        user: {
          username: updatedUser.username,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          role: updatedUser.role,
          accountStatus: updatedUser.accountStatus,
          assignedAgent: updatedUser.assignedAgent,
        },
      });
    });
  } catch (err) {
    console.error("Error updating user", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.notifications = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    // Verify the token
    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Unauthorized access" });
      }

      // Find the current user and populate their notifications
      const user = await User.findById(decodedToken.id).populate(
        "notifications"
      );

      if (!user) {
        return res
          .status(404)
          .json({ status: false, message: "User not found" });
      }

      // Return the user's notifications
      res.json(user.notifications);
    });
  } catch (err) {
    console.error("Error fetching notifications", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.deleteNotification = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    // Verify the token
    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Unauthorized access" });
      }

      const userId = decodedToken.id; // Get the current user's ID
      const notificationId = req.params.id; // Get the notification ID from the request

      // Find the current user
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if the notification exists in the user's notifications array
      const notificationIndex = user.notifications.indexOf(notificationId);

      if (notificationIndex === -1) {
        return res
          .status(404)
          .json({ message: "Notification not found in user's notifications" });
      }

      // Remove the notification ID from the user's notifications array
      user.notifications.splice(notificationIndex, 1);
      await user.save();

      res.json({ message: "Notification deleted successfully" });
    });
  } catch (err) {
    console.error("Error deleting notification", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.getTransactions = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
        if (err) {
          return res
            .status(401)
            .json({ status: false, message: "Unauthorized access" });
        }

        try {
          const userId = decodedToken.id;

          // Fetch all submissions for this user
          const submissions = await Submission.find({ user: userId });

          // Calculate totals for deposits and withdrawals
          const totalDeposit = submissions
            .filter(
              (submission) =>
                submission.type === "deposit" &&
                submission.status === "approved"
            )
            .reduce((sum, submission) => sum + submission.amount, 0);

          const totalWithdraw = submissions
            .filter(
              (submission) =>
                submission.type === "withdrawal" &&
                submission.status === "approved"
            )
            .reduce((sum, submission) => sum + submission.amount, 0);

          // Send the calculated totals to the frontend
          res.json({
            status: true,
            totalDeposit,
            totalWithdraw,
          });
        } catch (error) {
          console.error("Error fetching transactions:", error);
          res.status(500).json({ error: "Internal Server Error" });
        }
      });
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
    }
  } catch (err) {
    console.error("Error Fetching transactions", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.getButtonLinks = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access, no token" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Unauthorized access" });
      }

      try {
        const buttonLinks = await ButtonLinksModel.findOne();
        if (!buttonLinks) {
          return res
            .status(404)
            .json({ status: false, message: "Links not found" });
        }

        res.json({ status: true, buttonLinks });
      } catch (error) {
        console.error("Error fetching button links:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });
  } catch (error) {
    console.error("Error fetching button links:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// Route to update the button links
module.exports.updateButtonLinks = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(401)
        .json({ status: false, message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        return res
          .status(401)
          .json({ status: false, message: "Unauthorized access" });
      }

      try {
        const { linkOne, linkTwo } = req.body;

        // Find and update or create new links entry
        const buttonLinks = await ButtonLinksModel.findOneAndUpdate(
          {},
          { linkOne, linkTwo },
          { new: true, upsert: true }
        );

        res.json({
          status: true,
          message: "Links updated successfully",
          buttonLinks,
        });
      } catch (error) {
        console.error("Error updating button links:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });
  } catch (error) {
    console.error("Error updating button links:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};
