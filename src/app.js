import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);
//  For json data
app.use(
  express.json({
    limit: "16kb",
  })
);
// for url encoding
app.use(express.urlencoded({ extended: true, limit: "16kb" }));

app.use(express.static("public"));

app.use(cookieParser());

// Routes
import userRouter from "./routes/user.route.js";

// routes declearation
app.use("/api/v1/users", userRouter);

export { app };
