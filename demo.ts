import express from "express";
import bodyParser from "body-parser";

import { createConfig, createSnaf } from "./src";

const app = express();
const port = 3005; // Port for test server

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// create our snaf
const snaf = createSnaf(
  createConfig({
    enabled: true,
    modules: {
      xss: {
        enabled: true,
        dynamicContent: true,
        urlParameters: true,
        formInputs: true,
        userGeneratedContent: true,
        blockMode: "block", // return http 403 Forbidden, like a WAF
        inlineEventHandlers: true,
      },
    },
  }),
);
// use snaf with timing middleware
app.use(async (req, res, next) => {
  const start = process.hrtime.bigint();
  await snaf.express()(req, res, () => {
    const end = process.hrtime.bigint();
    const durationMs = Number(end - start) / 1_000_000;
    console.log(`🕒 snaf middleware took ${durationMs.toFixed(2)} ms`);
    next();
  });
});

app.get("/", (req, res) => {
  const payload = req.query.q || "";
  res.send(`
    <!DOCTYPE html>
    <html lang="ts">
    <head><title>XSS Test</title></head>
    <body>
      <h1>XSS Reflection Test</h1>
      <form method="GET">
        <input name="q" placeholder="Try something evil..." />
        <button type="submit">Submit</button>
      </form>
      <hr>
      <div>User input:</div>
      <div id="reflect">${payload}</div>
    </body>
    </html>
  `);
});

app.post("/post", (req, res) => {
  const payload = req.body.q || "";
  res.send(`
    <div>POST Reflection:</div>
    <div id="reflect-post">${payload}</div>
  `);
});

app.listen(port, () => {
  console.log(`🚨 XSS test server listening at http://localhost:${port}`);
});
