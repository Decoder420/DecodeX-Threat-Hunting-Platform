import Sidebar from "./Sidebar";

export default function AppLayout({ children, onLogout }) {
  return (
    <div className="soc-layout">
      <Sidebar onLogout={onLogout} />
      <div className="soc-layout__main">{children}</div>
    </div>
  );
}
