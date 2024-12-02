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
    } else {
      file = "";
    }

    const token = req.cookies.jwt;

    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
        if (err) {
          res.json({ status: false });
          next();
        } else {
          const user = await User.findById(decodedToken.id);
          const userId = decodedToken.id;

          if (!paymentMethod || !amount || !file) {
            return res.status(400).json({
              error: "Payment method, amount, and screenshot are required.",
            });
          }

          const newSubmission = new Submission({
            user: userId,
            type: "deposit",
            username: user.username,
            phoneNumber: user.phoneNumber, // Change to phoneNumber
            amount,
            paymentMethod,
            file,
          });

          const notification = `${user.username} did a deposit`;

          const newNotification = new Notification({
            type: "deposit",
            notification: notification,
          });

          await newNotification.save();

          // Save the submission
          const savedSubmission = await newSubmission.save();

          // Add submission to user's submissions array
          user.submissions.push(savedSubmission._id);
          await user.save();

          res.status(201).json({
            message: "Deposit submission created successfully.",
            submission: savedSubmission,
          });
        }
      });
    } else {
      res.json({ status: false });
      next();
    }
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

    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
        if (err) {
          res
            .status(401)
            .json({ status: false, message: "Unauthorized access" });
          next();
        } else {
          const user = await User.findById(decodedToken.id);
          const userId = decodedToken.id;

          if (!paymentGateway || !amount || !accountName || !accountNumber) {
            return res.status(400).json({
              error:
                "Payment gateway, account name, account number, and amount are required.",
            });
          }

          const newSubmission = new Submission({
            user: userId,
            type: "withdrawal",
            username: user.username,
            phoneNumber: user.phoneNumber, // Change to phoneNumber
            amount,
            paymentGateway,
            bankName,
            accountName,
            accountNumber,
          });

          // Save the submission
          const savedSubmission = await newSubmission.save();

          const notification = `${user.username} requests a withdraw`;

          const newNotification = new Notification({
            type: "withdraw",
            notification: notification,
          });

          await newNotification.save();

          // Add submission to user's submissions array
          user.submissions.push(savedSubmission._id);
          await user.save();

          res.status(201).json({
            message: "Withdrawal submission created successfully.",
            submission: savedSubmission,
          });
        }
      });
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (error) {
    console.error("Error creating withdrawal submission:", error);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.submissions = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (token) {
      try {
        // Decode the JWT token to get the logged-in user details
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const loggedInUser = await User.findById(decoded.id); // Use decoded.id for user ID

        // Fetch all submissions and populate the user field
        const submissions = await Submission.find().populate("user");

        if (loggedInUser.role === "admin") {
          // If the user is an admin, return all submissions
          res.json(submissions);
        } else if (loggedInUser.role === "agent") {
          // If the user is an agent, filter the submissions by assignedAgent
          const filteredSubmissions = submissions.filter((submission) => {
            return (
              submission.user.assignedAgent &&
              submission.user.assignedAgent.toString() ===
                loggedInUser._id.toString()
            );
          });
          res.json(filteredSubmissions);
        } else {
          // If the role is neither admin nor agent
          res.status(403).json({
            message: "You are not authorized to view these submissions.",
          });
        }
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error fetching submissions" });
      }
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Fetching Submissions", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.updateSubmission = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      const { id } = req.params;
      const { status } = req.body;

      if (!["pending", "approved", "declined"].includes(status)) {
        return res.status(400).json({ message: "Invalid status value" });
      }

      try {
        const submission = await Submission.findById(id);

        if (!submission) {
          return res.status(404).json({ message: "Submission not found" });
        }

        submission.status = status;
        await submission.save();

        res.json({
          message: "Submission status updated successfully",
          submission,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error updating submission status" });
      }
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Fetching Submissions", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.deleteSubmission = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (token) {
      const { id } = req.params;

      try {
        const submission = await Submission.findById(id);

        if (!submission) {
          return res.status(404).json({ message: "Submission not found" });
        }

        await Submission.findByIdAndDelete(id);

        res.json({
          message: "Submission deleted successfully",
        });
      } catch (err) {
        console.error("Error deleting submission:", err);
        res.status(500).json({ message: "Error deleting submission" });
      }
    } else {
      res.status(401).json({ status: false, message: "Unauthorized access" });
      next();
    }
  } catch (err) {
    console.error("Error Deleting Submission", err);
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
      const loggedInUser = await User.findById(userId).select("role");
      if (!loggedInUser) {
        return res.status(404).json({ message: "User not found" });
      }

      let users;

      // Check if the logged-in user is an agent
      if (loggedInUser.role === "agent") {
        // Find users assigned to this agent
        users = await User.find({ assignedAgent: userId }).populate(
          "assignedAgent",
          "firstName lastName username role"
        );
      } else if (loggedInUser.role === "admin") {
        // Admin can view all users
        users = await User.find().populate(
          "assignedAgent",
          "firstName lastName username role"
        );
      } else {
        return res.status(403).json({ message: "Access denied" });
      }

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
        const user = await User.findOneAndDelete({
          username: req.params.username,
        });
        if (!user) return res.status(404).json({ message: "User not found" });
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
      if (!requestingUser || requestingUser.role !== "admin") {
        return res
          .status(403)
          .json({ status: false, message: "Insufficient permissions" });
      }

      const { username } = req.params;
      const { firstName, lastName, role, accountStatus, assignedAgent } =
        req.body;

      // Validate assignedAgent field if provided
      if (assignedAgent) {
        const agent = await User.findById(assignedAgent);
        if (!agent || agent.role !== "agent") {
          return res
            .status(400)
            .json({ status: false, message: "Invalid assigned agent ID" });
        }
      }

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
      } else {
        const user = await User.findById(decodedToken.id);
        if (user.role !== "user") {
          try {
            const notifications = await Notification.find();
            res.json(notifications);
          } catch (error) {
            console.error("Error fetching notifications: ", error);
            res.status(500).json({ error: "Internal Server Error" });
          }
        } else {
          return res
            .status(401)
            .json({ status: false, message: "Unauthorized access" });
        }
      }
    });
  } catch (err) {
    console.error("Error updating user", err);
    res.status(500).json({ error: "Internal server error." });
  }
};

module.exports.deleteNotification = async (req, res, next) => {
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
      } else {
        const user = await User.findById(decodedToken.id);

        if (user.role !== "user") {
          try {
            const notificationId = req.params.id;
            const notification = await Notification.findByIdAndDelete(
              notificationId
            );

            if (!notification) {
              return res
                .status(404)
                .json({ message: "Notification not found" });
            }

            res.json({ message: "Notification deleted successfully" });
          } catch (error) {
            console.error("Error deleting notification: ", error);
            res.status(500).json({ error: "Internal Server Error" });
          }
        } else {
          return res
            .status(401)
            .json({ status: false, message: "Unauthorized access" });
        }
      }
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
        .json({ status: false, message: "Unauthorized access" });
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
