const multer = require("multer");
const { login, register } = require("../Controllers/AuthControllers");
const {
  checkUser,
  deposit,
  withdraw,
  submissions,
  updateSubmission,
  deleteSubmission,
  getAccountDetails,
  updateAccountDetails,
  getUsers,
  deleteUsers,
  depositHistory,
  withdrawHistory,
  updateUser,
  notifications,
  deleteNotification,
  getTransactions,
} = require("../Middlewares/AuthMiddlewares");

const router = require("express").Router();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Set the destination folder for uploaded files
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname); // Set the filename to be unique
  },
});

const upload = multer({ storage: storage });

router.post("/login", login);
router.post("/register", register);
router.post("/", checkUser);
router.post("/deposit", upload.single("file"), deposit);
router.post("/withdraw", withdraw);
router.get("/submissions", submissions);
router.put("/submissions/:id", updateSubmission);
router.delete("/submissions/:id", deleteSubmission);
router.get("/account-details", getAccountDetails);
router.post("/account-details", updateAccountDetails);
router.get("/get-users", getUsers);
router.get("/transactions", getTransactions);
router.delete("/users/:username", deleteUsers);
router.put("/users/:username", updateUser);
router.get("/submissions/:username", depositHistory);
router.get("/submissions/w/:username", withdrawHistory);
router.get("/notifications", notifications);
router.delete("/delete-notification/:id", deleteNotification);

module.exports = router;
