/**
 * Cyber Shield SOC — Canvas Visualizers & Real-Time Telemetry Charts
 * Includes: Topological Network HUD, Microsecond Telemetry Chart,
 * 24-Hour Trend Spline, and Multi-Metric Hardware Ingestion Chart.
 */

class NetworkVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.particles = [];
    this.pulses = [];

    this.nodes = {
      external: { id: 'external', label: 'External Ingress', x: 0.12, y: 0.5, type: 'cloud', color: '#94a3b8' },
      firewall: { id: 'firewall', label: 'Perimeter IPS', x: 0.35, y: 0.5, type: 'shield', color: '#00f2fe' },
      dmzWeb:   { id: 'dmzWeb',   label: 'DMZ Gateway (10.0.4.15)', x: 0.60, y: 0.30, type: 'server', color: '#10b981' },
      authSso:  { id: 'authSso',  label: 'IAM / SSO Gateway', x: 0.60, y: 0.70, type: 'key', color: '#8b5cf6' },
      database: { id: 'database', label: 'Customer DB (10.0.8.22)', x: 0.85, y: 0.30, type: 'db', color: '#38bdf8' },
      internalWorkstations: { id: 'internal', label: 'Shielded Mobile & LAN', x: 0.85, y: 0.70, type: 'lan', color: '#10b981' }
    };

    this.links = [
      { from: 'external', to: 'firewall' },
      { from: 'firewall', to: 'dmzWeb' },
      { from: 'firewall', to: 'authSso' },
      { from: 'dmzWeb', to: 'database' },
      { from: 'authSso', to: 'internalWorkstations' }
    ];

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.animate();
  }

  resize() {
    if (!this.canvas) return;
    this.width = this.canvas.parentElement.clientWidth;
    this.height = this.canvas.parentElement.clientHeight || 320;
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  triggerFlow(flow) {
    const isThreat = flow.isThreat;
    let fromNode = this.nodes.external;
    let toNode = this.nodes.firewall;

    if (flow.dstPort === 22 || flow.protocol === 'HTTPS/AUTH') {
      toNode = this.nodes.authSso;
    } else if (flow.dstPort === 3306 || flow.prediction === 'DATA_EXFILTRATION') {
      toNode = this.nodes.database;
    } else {
      toNode = this.nodes.dmzWeb;
    }

    const startX = fromNode.x * this.width;
    const startY = fromNode.y * this.height;
    const endX = toNode.x * this.width;
    const endY = toNode.y * this.height;

    const count = isThreat ? 6 : 2;
    for (let i = 0; i < count; i++) {
      this.particles.push({
        x: startX,
        y: startY,
        startX,
        startY,
        endX,
        endY,
        progress: -i * 0.15,
        speed: isThreat ? 0.025 : 0.015,
        color: isThreat ? '#ff3366' : '#10b981',
        size: isThreat ? 4 : 2.5,
        isThreat
      });
    }

    if (isThreat) {
      this.pulses.push({
        x: this.nodes.firewall.x * this.width,
        y: this.nodes.firewall.y * this.height,
        radius: 5,
        maxRadius: 45,
        color: 'rgba(255, 51, 102, ',
        alpha: 0.9
      });
    }
  }

  animate() {
    if (!this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    // Links
    this.ctx.lineWidth = 1.5;
    for (const link of this.links) {
      const n1 = this.nodes[link.from];
      const n2 = this.nodes[link.to];
      const x1 = n1.x * this.width;
      const y1 = n1.y * this.height;
      const x2 = n2.x * this.width;
      const y2 = n2.y * this.height;

      const grad = this.ctx.createLinearGradient(x1, y1, x2, y2);
      grad.addColorStop(0, 'rgba(56, 189, 248, 0.15)');
      grad.addColorStop(1, 'rgba(0, 242, 254, 0.3)');

      this.ctx.beginPath();
      this.ctx.strokeStyle = grad;
      this.ctx.moveTo(x1, y1);
      this.ctx.lineTo(x2, y2);
      this.ctx.stroke();
    }

    // Particles
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.progress += p.speed;

      if (p.progress > 0) {
        const curX = p.startX + (p.endX - p.startX) * Math.min(p.progress, 1);
        const curY = p.startY + (p.endY - p.startY) * Math.min(p.progress, 1);

        this.ctx.beginPath();
        this.ctx.arc(curX, curY, p.size, 0, Math.PI * 2);
        this.ctx.fillStyle = p.color;
        this.ctx.shadowColor = p.color;
        this.ctx.shadowBlur = p.isThreat ? 12 : 6;
        this.ctx.fill();
        this.ctx.shadowBlur = 0;
      }

      if (p.progress >= 1) this.particles.splice(i, 1);
    }

    // Pulses
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const pulse = this.pulses[i];
      pulse.radius += 1.4;
      pulse.alpha -= 0.025;

      if (pulse.alpha <= 0) {
        this.pulses.splice(i, 1);
        continue;
      }

      this.ctx.beginPath();
      this.ctx.arc(pulse.x, pulse.y, pulse.radius, 0, Math.PI * 2);
      this.ctx.strokeStyle = `${pulse.color}${pulse.alpha})`;
      this.ctx.lineWidth = 2;
      this.ctx.stroke();
    }

    // Nodes
    for (const key in this.nodes) {
      const n = this.nodes[key];
      const x = n.x * this.width;
      const y = n.y * this.height;

      this.ctx.beginPath();
      this.ctx.arc(x, y, 16, 0, Math.PI * 2);
      this.ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
      this.ctx.strokeStyle = n.color;
      this.ctx.lineWidth = 2;
      this.ctx.shadowColor = n.color;
      this.ctx.shadowBlur = 10;
      this.ctx.fill();
      this.ctx.stroke();
      this.ctx.shadowBlur = 0;

      this.ctx.beginPath();
      this.ctx.arc(x, y, 6, 0, Math.PI * 2);
      this.ctx.fillStyle = n.color;
      this.ctx.fill();

      this.ctx.fillStyle = '#f1f5f9';
      this.ctx.font = '600 11px sans-serif';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(n.label, x, y + 28);
    }

    requestAnimationFrame(() => this.animate());
  }
}

class TelemetryChart {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.dataPoints = [];
    this.maxPoints = 40;

    for (let i = 0; i < this.maxPoints; i++) {
      this.dataPoints.push({ throughput: 20 + Math.random() * 25, anomaly: 0.1 + Math.random() * 0.1 });
    }

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.render();
  }

  resize() {
    if (!this.canvas) return;
    this.width = this.canvas.parentElement.clientWidth;
    this.height = this.canvas.parentElement.clientHeight || 180;
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  addDataPoint(throughput, anomalyScore) {
    this.dataPoints.push({
      throughput: Math.min(throughput, 1500),
      anomaly: anomalyScore || 0.1
    });
    if (this.dataPoints.length > this.maxPoints) {
      this.dataPoints.shift();
    }
    this.render();
  }

  render() {
    if (!this.ctx) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    this.ctx.lineWidth = 1;
    for (let y = 30; y < this.height; y += 35) {
      this.ctx.beginPath();
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(this.width, y);
      this.ctx.stroke();
    }

    const step = this.width / (this.maxPoints - 1);
    const maxThroughput = 800;

    // Throughput Area
    this.ctx.beginPath();
    this.ctx.moveTo(0, this.height);
    for (let i = 0; i < this.dataPoints.length; i++) {
      const x = i * step;
      const norm = Math.min(this.dataPoints[i].throughput / maxThroughput, 1);
      const y = this.height - norm * (this.height - 30) - 10;
      this.ctx.lineTo(x, y);
    }
    this.ctx.lineTo(this.width, this.height);
    this.ctx.closePath();

    const areaGrad = this.ctx.createLinearGradient(0, 0, 0, this.height);
    areaGrad.addColorStop(0, 'rgba(0, 242, 254, 0.25)');
    areaGrad.addColorStop(1, 'rgba(0, 242, 254, 0.0)');
    this.ctx.fillStyle = areaGrad;
    this.ctx.fill();

    // Throughput Stroke
    this.ctx.beginPath();
    for (let i = 0; i < this.dataPoints.length; i++) {
      const x = i * step;
      const norm = Math.min(this.dataPoints[i].throughput / maxThroughput, 1);
      const y = this.height - norm * (this.height - 30) - 10;
      if (i === 0) this.ctx.moveTo(x, y);
      else this.ctx.lineTo(x, y);
    }
    this.ctx.strokeStyle = '#00f2fe';
    this.ctx.lineWidth = 2;
    this.ctx.stroke();

    // Anomaly Line
    this.ctx.beginPath();
    for (let i = 0; i < this.dataPoints.length; i++) {
      const x = i * step;
      const aNorm = Math.min(this.dataPoints[i].anomaly, 1);
      const y = this.height - aNorm * (this.height - 30) - 10;
      if (i === 0) this.ctx.moveTo(x, y);
      else this.ctx.lineTo(x, y);
    }
    this.ctx.strokeStyle = '#ff3366';
    this.ctx.lineWidth = 2;
    this.ctx.setLineDash([4, 4]);
    this.ctx.stroke();
    this.ctx.setLineDash([]);

    // Threshold Line
    const threshY = this.height - 0.65 * (this.height - 30) - 10;
    this.ctx.strokeStyle = 'rgba(245, 158, 11, 0.5)';
    this.ctx.lineWidth = 1;
    this.ctx.setLineDash([2, 4]);
    this.ctx.beginPath();
    this.ctx.moveTo(0, threshY);
    this.ctx.lineTo(this.width, threshY);
    this.ctx.stroke();
    this.ctx.setLineDash([]);

    this.ctx.fillStyle = '#f59e0b';
    this.ctx.font = '10px monospace';
    this.ctx.fillText('ANOMALY THRESHOLD (0.65)', 10, threshY - 4);
  }
}

class AlertTrendChart {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.labels = ['12h', '11h', '10h', '9h', '8h', '7h', '6h', '5h', '4h', '3h', '2h', 'Now'];
    this.data = [8, 12, 9, 15, 22, 18, 14, 25, 31, 28, 38, 42];

    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.render();
  }

  resize() {
    if (!this.canvas) return;
    this.width = this.canvas.parentElement.clientWidth || 400;
    this.height = this.canvas.parentElement.clientHeight || 180;
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    this.render();
  }

  updateData(labels, data) {
    if (labels && labels.length) this.labels = labels;
    if (data && data.length) this.data = data;
    this.render();
  }

  render() {
    if (!this.ctx || !this.data.length) return;
    this.ctx.clearRect(0, 0, this.width, this.height);

    const pad = { top: 20, right: 20, bottom: 30, left: 35 };
    const chartW = this.width - pad.left - pad.right;
    const chartH = this.height - pad.top - pad.bottom;
    const maxVal = Math.max(...this.data, 20);

    this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    this.ctx.lineWidth = 1;
    this.ctx.fillStyle = '#64748b';
    this.ctx.font = '10px monospace';

    const steps = 4;
    for (let i = 0; i <= steps; i++) {
      const y = pad.top + (chartH / steps) * i;
      const val = Math.round(maxVal - (maxVal / steps) * i);
      this.ctx.beginPath();
      this.ctx.moveTo(pad.left, y);
      this.ctx.lineTo(this.width - pad.right, y);
      this.ctx.stroke();
      this.ctx.fillText(String(val), 8, y + 3);
    }

    const step = chartW / (this.data.length - 1);

    // Area
    this.ctx.beginPath();
    this.ctx.moveTo(pad.left, pad.top + chartH);
    for (let i = 0; i < this.data.length; i++) {
      const x = pad.left + i * step;
      const y = pad.top + chartH - (this.data[i] / maxVal) * chartH;
      this.ctx.lineTo(x, y);
    }
    this.ctx.lineTo(pad.left + (this.data.length - 1) * step, pad.top + chartH);
    this.ctx.closePath();

    const areaGrad = this.ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
    areaGrad.addColorStop(0, 'rgba(0, 242, 254, 0.35)');
    areaGrad.addColorStop(0.6, 'rgba(56, 189, 248, 0.12)');
    areaGrad.addColorStop(1, 'rgba(0, 242, 254, 0.0)');
    this.ctx.fillStyle = areaGrad;
    this.ctx.fill();

    // Line
    this.ctx.beginPath();
    for (let i = 0; i < this.data.length; i++) {
      const x = pad.left + i * step;
      const y = pad.top + chartH - (this.data[i] / maxVal) * chartH;
      if (i === 0) this.ctx.moveTo(x, y);
      else this.ctx.lineTo(x, y);
    }
    this.ctx.strokeStyle = '#00f2fe';
    this.ctx.lineWidth = 2.5;
    this.ctx.stroke();

    // Dots
    for (let i = 0; i < this.data.length; i++) {
      const x = pad.left + i * step;
      const y = pad.top + chartH - (this.data[i] / maxVal) * chartH;

      this.ctx.beginPath();
      this.ctx.arc(x, y, 3.5, 0, Math.PI * 2);
      this.ctx.fillStyle = '#060911';
      this.ctx.fill();
      this.ctx.lineWidth = 2;
      this.ctx.strokeStyle = '#00f2fe';
      this.ctx.stroke();

      if (i % 2 === 0 || i === this.data.length - 1) {
        this.ctx.fillStyle = '#94a3b8';
        this.ctx.font = '9px monospace';
        const label = this.labels[i] || '';
        this.ctx.fillText(label, x - 12, this.height - 8);
      }
    }
  }
}

window.NetworkVisualizer = NetworkVisualizer;
window.TelemetryChart = TelemetryChart;
window.AlertTrendChart = AlertTrendChart;
