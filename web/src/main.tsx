import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./ui/App.js";
import "./ui/styles.css";

const container = document.querySelector("#root");
if (container === null) {
    throw new Error("Missing #root container");
}

createRoot(container).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
