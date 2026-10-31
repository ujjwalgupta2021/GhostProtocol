/**
 * GhostProtocol Interactive Particle & Neural Network Canvas
 * Generates an interactive, lightweight 60fps constellation mesh background
 * that responds dynamically to mouse movement and theme switches.
 */

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  baseAlpha: number;
}

export class ParticleNetwork {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private particles: Particle[] = [];
  private mouseX: number = -1000;
  private mouseY: number = -1000;
  private isDark: boolean = true;
  private animFrameId: number | null = null;
  private isRunning: boolean = false;

  private readonly maxDistance = 125;
  private readonly mouseDistance = 160;

  constructor(canvasId: string, initialDark: boolean = true) {
    this.canvas = document.getElementById(canvasId) as HTMLCanvasElement;
    if (!this.canvas) {
      throw new Error(`Canvas #${canvasId} not found`);
    }
    this.ctx = this.canvas.getContext('2d')!;
    this.isDark = initialDark;

    this.resizeCanvas();
    this.initParticles();
    this.bindEvents();
    this.start();
  }

  public setDarkTheme(isDark: boolean): void {
    this.isDark = isDark;
  }

  private resizeCanvas(): void {
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = window.innerWidth * dpr;
    this.canvas.height = window.innerHeight * dpr;
    this.canvas.style.width = `${window.innerWidth}px`;
    this.canvas.style.height = `${window.innerHeight}px`;
    this.ctx.scale(dpr, dpr);
  }

  private initParticles(): void {
    this.particles = [];
    const area = window.innerWidth * window.innerHeight;
    // Calculate balanced particle density based on screen resolution
    const count = Math.min(Math.floor(area / 18000), 75);

    for (let i = 0; i < count; i++) {
      this.particles.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        vx: (Math.random() - 0.5) * 0.7,
        vy: (Math.random() - 0.5) * 0.7,
        radius: Math.random() * 1.5 + 1.2,
        baseAlpha: Math.random() * 0.4 + 0.3,
      });
    }
  }

  private bindEvents(): void {
    window.addEventListener('resize', () => {
      this.resizeCanvas();
      this.initParticles();
    });

    window.addEventListener('mousemove', (e) => {
      this.mouseX = e.clientX;
      this.mouseY = e.clientY;
    });

    window.addEventListener('mouseleave', () => {
      this.mouseX = -1000;
      this.mouseY = -1000;
    });

    // Pause when tab is not active to conserve battery & GPU
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.stop();
      } else {
        this.start();
      }
    });
  }

  private start(): void {
    if (!this.isRunning) {
      this.isRunning = true;
      this.tick();
    }
  }

  private stop(): void {
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
    this.isRunning = false;
  }

  private tick = (): void => {
    if (!this.isRunning) return;
    this.render();
    this.animFrameId = requestAnimationFrame(this.tick);
  };

  private render(): void {
    const width = window.innerWidth;
    const height = window.innerHeight;
    this.ctx.clearRect(0, 0, width, height);

    // Color definitions for Dark vs Light theme
    const particleColor = this.isDark ? 'rgba(6, 182, 212, ' : 'rgba(14, 165, 233, ';
    const lineColor = this.isDark ? '6, 182, 212' : '59, 130, 246';
    const mouseLineColor = this.isDark ? '56, 189, 248' : '14, 165, 233';

    // Update positions & draw particles
    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];

      p.x += p.vx;
      p.y += p.vy;

      // Bounce at edges
      if (p.x < 0 || p.x > width) p.vx *= -1;
      if (p.y < 0 || p.y > height) p.vy *= -1;

      // Draw particle dot
      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = `${particleColor}${p.baseAlpha})`;
      this.ctx.fill();

      // Connect with nearby particles
      for (let j = i + 1; j < this.particles.length; j++) {
        const p2 = this.particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < this.maxDistance) {
          const alpha = (1 - dist / this.maxDistance) * (this.isDark ? 0.22 : 0.15);
          this.ctx.beginPath();
          this.ctx.moveTo(p.x, p.y);
          this.ctx.lineTo(p2.x, p2.y);
          this.ctx.strokeStyle = `rgba(${lineColor}, ${alpha})`;
          this.ctx.lineWidth = 0.8;
          this.ctx.stroke();
        }
      }

      // Connect with mouse cursor if nearby
      if (this.mouseX > 0 && this.mouseY > 0) {
        const mdx = p.x - this.mouseX;
        const mdy = p.y - this.mouseY;
        const mDist = Math.sqrt(mdx * mdx + mdy * mdy);

        if (mDist < this.mouseDistance) {
          const mAlpha = (1 - mDist / this.mouseDistance) * (this.isDark ? 0.45 : 0.35);
          this.ctx.beginPath();
          this.ctx.moveTo(p.x, p.y);
          this.ctx.lineTo(this.mouseX, this.mouseY);
          this.ctx.strokeStyle = `rgba(${mouseLineColor}, ${mAlpha})`;
          this.ctx.lineWidth = 1.2;
          this.ctx.stroke();
        }
      }
    }
  }
}
