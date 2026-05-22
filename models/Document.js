const mongoose = require("mongoose");

const documentSchema = new mongoose.Schema(
  {
    filename: {
      type: String,
      required: true
    },

    originalName: {
      type: String,
      required: true
    },

    path: {
      type: String,
      required: true
    },

    hash: {
      type: String,
      required: true
    },

    encrypted: {
      type: Boolean,
      default: true
    },

    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    signature: {
  type: String,
  required: true
}
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("Document", documentSchema);