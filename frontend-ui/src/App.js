import React, { useState } from "react";
import "./App.css";
import Logs from "./components/Logs";
import GraphView from "./GraphView"; // Graph visualization component

function App() {
  const [input, setInput] = useState("");
  const [mode, setMode] = useState("ip"); // ip, domain, hash, shodan
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const scan = async () => {
    try {
      const endpointMap = {
        ip: `/check/ip?ip=${input}`,
        domain: `/check/domain?domain=${input}`,
        hash: `/check/hash?hash=${input}`,
        shodan: `/scan/shodan?ip=${input}`,
      };

      const res = await fetch(`http://192.168.15.128:8000${endpointMap[mode]}`);
      const data = await res.json();
      setResult(data);
      setError("");
    } catch (err) {
      setError("Failed to fetch result. Check API or CORS config.");
      setResult(null);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white px-4">
      <h1 className="text-3xl font-bold mb-6">Threat Intelligence Dashboard</h1>

      <div className="bg-gray-800 p-6 rounded-lg w-full max-w-md">
        <label className="block mb-2 font-semibold">Select Scan Type</label>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value)}
          className="w-full p-2 mb-4 bg-gray-700 rounded text-white"
        >
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="hash">Hash</option>
          <option value="shodan">Shodan</option>
        </select>

        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={`Enter ${mode}...`}
          className="w-full p-2 mb-4 bg-gray-700 rounded text-white"
        />
        <button
          onClick={scan}
          className="w-full bg-blue-600 hover:bg-blue-700 p-2 rounded font-semibold"
        >
          Scan
        </button>

        {error && (
          <div className="mt-4 p-3 bg-red-800 text-red-100 rounded">
            {error}
          </div>
        )}

        {result && (
          <div className="mt-4 p-4 bg-gray-700 rounded break-words">
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* Show logs and graph */}
      <Logs type={mode} />
      <GraphView />
    </div>
  );
}

export default App;

