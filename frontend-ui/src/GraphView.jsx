import React, { useEffect, useRef, useState } from 'react';
import { ForceGraph2D } from 'react-force-graph';

const GraphView = () => {
  const fgRef = useRef();
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  useEffect(() => {
    const fetchData = async () => {
      const res = await fetch('http://192.168.15.128:8000/graph/ip-verdict');
      const data = await res.json();
      setGraphData(data);
    };
    fetchData();
  }, []);

  const exportGraph = () => {
    // Get canvas from ForceGraph2D
    const canvas = fgRef.current && fgRef.current.renderer().domElement;
    if (canvas) {
      const dataUrl = canvas.toDataURL("image/png");
      const link = document.createElement('a');
      link.download = 'threat-graph.png';
      link.href = dataUrl;
      link.click();
    } else {
      alert('Graph not ready');
    }
  };

  return (
    <div className="p-4">
      <h2 className="text-xl mb-2">Threat Graph View</h2>
      <div style={{ height: '500px' }}>
        <ForceGraph2D
          ref={fgRef}
          graphData={graphData}
          nodeLabel="id"
          linkLabel="label"
        />
      </div>
      <button onClick={exportGraph} className="mt-4 bg-blue-600 p-2 rounded text-white">
        Export PNG
      </button>
    </div>
  );
};

export default GraphView;
