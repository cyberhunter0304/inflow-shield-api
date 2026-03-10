// Exact DOM from renderHeader()
export default function PageHeader() {
  return (
    <div className="page-header">
      <div className="logo-box">
        <img src="/loco.png" alt="iNextLabs" />
      </div>
      <div className="dashboard-header">
        <div className="header-content">
          <div className="dashboard-title">inFlow Shield</div>
          <div className="dashboard-subtitle">Real-time monitoring of AI security guardrails and threat detection</div>
        </div>
      </div>
    </div>
  );
}
