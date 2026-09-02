# CVShield Frontend v2

Premium cyber-security styled React/Vite frontend for the existing assurance backend.

Includes image, video, file, folder and URL provenance modes; drag-and-drop; batch folder selection; timeout/error handling; risk monitor; evidence result; audit view.

The URL mode deliberately does not fetch remote content in the browser. It validates the HTTP/HTTPS URL and fingerprints the URL string locally. Genuine remote-content analysis needs a server-side URL ingestion endpoint.

Render settings: Root Directory `frontend`; Build `npm install && npm run build`; Publish `dist`; `VITE_API_URL=https://trustguard-ai-sih26228.onrender.com`.
