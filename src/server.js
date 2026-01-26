import express from "express";
import cookieParser from "cookie-parser";

const app = express();

// Canvas stuurt vaak form-encoded POSTs
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Health check
app.get("/", (req, res) => {
  res.status(200).send("OK - tool is running");
});

// Placeholder routes (vullen we later in)
app.get("/lti/oidc/init", (req, res) => {
  res.status(200).send("OIDC init endpoint - coming next");
});

app.post("/lti/launch", (req, res) => {
  res.status(200).send("Launch endpoint - coming next");
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
