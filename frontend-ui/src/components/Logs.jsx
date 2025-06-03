import React, { useEffect, useState } from 'react';
import axios from 'axios';

const Logs = ({ type }) => {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await axios.get(`http://192.168.15.128:8000/logs/${type}`);
        setLogs(response.data);
      } catch (error) {
        console.error("Error fetching logs:", error);
      }
    };

    fetchLogs();
  }, [type]);

  return (
    <div className="bg-gray-800 text-white p-4 rounded-lg mt-6">
      <h2 className="text-xl mb-4 capitalize">{type} Logs</h2>
      <ul className="space-y-2">
        {logs.map((log, index) => (
          <li key={index} className="bg-gray-700 p-2 rounded">
            <pre>{JSON.stringify(log, null, 2)}</pre>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default Logs;
