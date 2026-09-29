import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";

// Pages (to be implemented)
const Dashboard = () => <div>SOC Dashboard</div>;
const Alerts = () => <div>Alerts</div>;
const Incidents = () => <div>Incidents</div>;
const Investigations = () => <div>Investigations</div>;
const ThreatIntel = () => <div>Threat Intelligence</div>;
const Settings = () => <div>Settings</div>;

function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-100">
        {/* Sidebar */}
        <nav className="w-64 bg-gray-900 text-white p-4">
          <h1 className="text-xl font-bold mb-8 text-red-500">SentinelAI</h1>
          <ul className="space-y-2">
            <li><a href="/" className="block p-2 hover:bg-gray-800 rounded">Dashboard</a></li>
            <li><a href="/alerts" className="block p-2 hover:bg-gray-800 rounded">Alerts</a></li>
            <li><a href="/incidents" className="block p-2 hover:bg-gray-800 rounded">Incidents</a></li>
            <li><a href="/investigations" className="block p-2 hover:bg-gray-800 rounded">Investigations</a></li>
            <li><a href="/threat-intel" className="block p-2 hover:bg-gray-800 rounded">Threat Intel</a></li>
            <li><a href="/settings" className="block p-2 hover:bg-gray-800 rounded">Settings</a></li>
          </ul>
        </nav>

        {/* Main Content */}
        <main className="flex-1 overflow-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/investigations" element={<Investigations />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
