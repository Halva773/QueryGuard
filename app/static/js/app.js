(function () {
  "use strict";

  const body = document.body;
  const sidebar = document.getElementById("sidebar");
  const menuButton = document.querySelector("[data-sidebar-toggle]");

  function closeMenu() {
    body.classList.remove("menu-open");
    if (menuButton) menuButton.setAttribute("aria-expanded", "false");
  }

  if (menuButton && sidebar) {
    menuButton.setAttribute("aria-controls", "sidebar");
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.addEventListener("click", function () {
      const open = body.classList.toggle("menu-open");
      menuButton.setAttribute("aria-expanded", String(open));
    });
    sidebar.addEventListener("click", function (event) {
      if (event.target.closest("a") && window.matchMedia("(max-width: 900px)").matches) {
        closeMenu();
      }
    });
    document.addEventListener("click", function (event) {
      if (
        body.classList.contains("menu-open") &&
        !sidebar.contains(event.target) &&
        !menuButton.contains(event.target)
      ) {
        closeMenu();
      }
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closeMenu();
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      const message = form.dataset.confirm || "Подтвердите действие";
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", async function () {
      const target = document.querySelector(button.dataset.copy);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.innerText);
        const initial = button.textContent;
        button.textContent = "✓";
        button.setAttribute("aria-label", "Скопировано");
        window.setTimeout(function () {
          button.textContent = initial;
          button.setAttribute("aria-label", "Скопировать SQL");
        }, 1600);
      } catch (_error) {
        const range = document.createRange();
        const selection = window.getSelection();
        range.selectNodeContents(target);
        selection.removeAllRanges();
        selection.addRange(range);
      }
    });
  });

  document.querySelectorAll(".toast").forEach(function (toast, index) {
    window.setTimeout(function () {
      toast.classList.add("is-leaving");
      window.setTimeout(function () { toast.remove(); }, 240);
    }, 4400 + index * 500);
  });

  function drawLineChart(canvas) {
    let points;
    try {
      points = JSON.parse(canvas.dataset.points || "[]");
    } catch (_error) {
      points = [];
    }

    const bounds = canvas.getBoundingClientRect();
    const width = Math.max(Math.round(bounds.width), 280);
    const height = Math.max(Math.round(bounds.height), 180);
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);

    const ctx = canvas.getContext("2d");
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const padding = { top: 16, right: 18, bottom: 31, left: 34 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    ctx.font = "10px Inter, ui-sans-serif, sans-serif";
    ctx.lineWidth = 1;
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (let value = 0; value <= 100; value += 25) {
      const y = padding.top + chartHeight - (value / 100) * chartHeight;
      ctx.strokeStyle = "#e2e9e5";
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();
      ctx.fillStyle = "#8a9690";
      ctx.fillText(String(value), padding.left - 8, y);
    }

    if (!points.length) {
      ctx.fillStyle = "#7b8982";
      ctx.textAlign = "center";
      ctx.font = "12px Inter, ui-sans-serif, sans-serif";
      ctx.fillText("Недостаточно данных для графика", width / 2, height / 2);
      return;
    }

    const xAt = function (index) {
      return padding.left + (points.length === 1 ? chartWidth / 2 : (index / (points.length - 1)) * chartWidth);
    };
    const yAt = function (value) {
      return padding.top + chartHeight - (Math.max(0, Math.min(100, value)) / 100) * chartHeight;
    };

    const gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartHeight);
    gradient.addColorStop(0, "rgba(22, 132, 91, 0.24)");
    gradient.addColorStop(1, "rgba(22, 132, 91, 0.015)");

    ctx.beginPath();
    points.forEach(function (point, index) {
      const x = xAt(index);
      const y = yAt(Number(point.value) || 0);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(xAt(points.length - 1), padding.top + chartHeight);
    ctx.lineTo(xAt(0), padding.top + chartHeight);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.beginPath();
    points.forEach(function (point, index) {
      const x = xAt(index);
      const y = yAt(Number(point.value) || 0);
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#16845b";
    ctx.lineWidth = 2.4;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    points.forEach(function (point, index) {
      const x = xAt(index);
      const y = yAt(Number(point.value) || 0);
      ctx.fillStyle = "#ffffff";
      ctx.beginPath();
      ctx.arc(x, y, 4.5, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = "#16845b";
      ctx.lineWidth = 2.2;
      ctx.stroke();
      ctx.fillStyle = "#74827b";
      ctx.font = "10px Inter, ui-sans-serif, sans-serif";
      ctx.fillText(String(point.label || ""), x, padding.top + chartHeight + 11);
    });
  }

  const charts = Array.from(document.querySelectorAll("canvas.line-chart"));
  charts.forEach(drawLineChart);
  if (charts.length) {
    let resizeTimer;
    window.addEventListener("resize", function () {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(function () { charts.forEach(drawLineChart); }, 120);
    });
  }
})();
