import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

// Bypass ThemeProvider temporarily to test rendering
createRoot(document.getElementById("root")!).render(
  <App />
);
