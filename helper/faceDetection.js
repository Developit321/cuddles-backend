const faceapi = require("face-api.js");
const tf = require("@tensorflow/tfjs-node"); // TensorFlow for Node.js
const { Canvas, Image, ImageData, loadImage, createCanvas } = require("canvas");
const path = require("path");

// Provide face-api.js with a canvas environment
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

// Load models required for face detection
const loadModels = async () => {
  try {
    const modelPath = path.join(__dirname, "model"); // Directory for models
    // Ensure the models are loaded asynchronously
    await faceapi.nets.ssdMobilenetv1.loadFromDisk(modelPath); // Main face detection model
    console.log("Models loaded successfully");
  } catch (error) {
    console.error("Error loading models:", error);
  }
};

// Detect faces in an image buffer
const detectFaces = async (imageBuffer) => {
  try {
    // Wait until models are loaded before detecting faces
    if (!faceapi.nets.ssdMobilenetv1.isLoaded) {
      console.log("Model is not loaded yet.");
      return false; // Return false if the model isn't loaded
    }

    const img = await loadImage(imageBuffer); // Load the image from the buffer
    const canvas = createCanvas(img.width, img.height);
    const ctx = canvas.getContext("2d");
    ctx.drawImage(img, 0, 0);

    // Detect faces
    const detections = await faceapi.detectAllFaces(canvas);

    if (detections.length === 0) {
      console.log("No faces detected.");
      return false; // No faces detected
    }

    console.log("Faces detected:", detections);
    return true; // Faces detected successfully
  } catch (error) {
    console.error("Error during face detection:", error);
    return false; // Error during detection
  }
};

// Ensure models are loaded before any detection is called
loadModels();

module.exports = { loadModels, detectFaces };
