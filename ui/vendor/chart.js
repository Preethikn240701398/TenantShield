/**
 * TenantShield Lightweight Offline Chart Utility
 * ==============================================
 * Renders restrained, accessible, single/two-hue charts using pure DOM SVG.
 * Designed to work 100% offline without remote CDNs or external dependencies.
 * Complies with strict Content Security Policy (no eval, no innerHTML).
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.TenantChart = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function createSvgElement(tag, attrs) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    if (attrs) {
      for (var key in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, key)) {
          el.setAttribute(key, attrs[key]);
        }
      }
    }
    return el;
  }

  function renderBarChart(container, options) {
    // Clear container safely
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }

    var data = options.data || [];
    var labelKey = options.labelKey || 'label';
    var valueKey = options.valueKey || 'value';
    var unit = options.unit || '';
    var title = options.title || '';

    if (data.length === 0) {
      var emptyNotice = document.createElement('div');
      emptyNotice.className = 'empty-state';
      emptyNotice.textContent = 'No chart data available.';
      container.appendChild(emptyNotice);
      return;
    }

    var width = options.width || 600;
    var height = options.height || 240;
    var padLeft = 70;
    var padRight = 30;
    var padTop = 30;
    var padBottom = 45;

    var chartW = width - padLeft - padRight;
    var chartH = height - padTop - padBottom;

    var maxVal = 0;
    for (var i = 0; i < data.length; i++) {
      var v = Number(data[i][valueKey]) || 0;
      if (v > maxVal) maxVal = v;
    }
    if (maxVal === 0) maxVal = 10;
    // Round maxVal up to clean number
    var niceMax = Math.ceil(maxVal * 1.15);

    var svg = createSvgElement('svg', {
      viewBox: '0 0 ' + width + ' ' + height,
      width: '100%',
      height: String(height),
      role: 'img',
      'aria-label': title || 'Metric bar chart'
    });
    svg.style.display = 'block';
    svg.style.fontFamily = 'system-ui, -apple-system, Segoe UI, sans-serif';

    // Grid lines (3 horizontal lines)
    var ticks = 4;
    for (var t = 0; t <= ticks; t++) {
      var tickVal = Math.round((niceMax / ticks) * t);
      var yPos = padTop + chartH - (t / ticks) * chartH;

      var line = createSvgElement('line', {
        x1: String(padLeft),
        y1: String(yPos),
        x2: String(width - padRight),
        y2: String(yPos),
        stroke: '#e0e0e0',
        'stroke-width': '1'
      });
      svg.appendChild(line);

      var tickText = createSvgElement('text', {
        x: String(padLeft - 8),
        y: String(yPos + 4),
        'text-anchor': 'end',
        'font-size': '11',
        fill: '#555555'
      });
      tickText.textContent = tickVal + (unit ? ' ' + unit : '');
      svg.appendChild(tickText);
    }

    // Baseline axis
    var axis = createSvgElement('line', {
      x1: String(padLeft),
      y1: String(padTop + chartH),
      x2: String(width - padRight),
      y2: String(padTop + chartH),
      stroke: '#1a1a1a',
      'stroke-width': '1'
    });
    svg.appendChild(axis);

    // Bars
    var barCount = data.length;
    var slotW = chartW / barCount;
    var barW = Math.max(16, Math.min(48, slotW * 0.55));

    for (var b = 0; b < barCount; b++) {
      var item = data[b];
      var rawVal = Number(item[valueKey]) || 0;
      var barH = (rawVal / niceMax) * chartH;
      var x = padLeft + b * slotW + (slotW - barW) / 2;
      var y = padTop + chartH - barH;

      var rect = createSvgElement('rect', {
        x: String(x),
        y: String(y),
        width: String(barW),
        height: String(Math.max(1, barH)),
        fill: '#005f73',
        rx: '2',
        ry: '2'
      });
      svg.appendChild(rect);

      // Value label on top of bar
      var valText = createSvgElement('text', {
        x: String(x + barW / 2),
        y: String(y - 4),
        'text-anchor': 'middle',
        'font-size': '11',
        'font-weight': '600',
        fill: '#1a1a1a'
      });
      valText.textContent = rawVal.toLocaleString(undefined, { maximumFractionDigits: 1 });
      svg.appendChild(valText);

      // Category label below axis
      var catText = createSvgElement('text', {
        x: String(x + barW / 2),
        y: String(padTop + chartH + 18),
        'text-anchor': 'middle',
        'font-size': '11',
        fill: '#1a1a1a'
      });
      var rawLabel = String(item[labelKey] || '');
      catText.textContent = rawLabel.length > 16 ? rawLabel.substring(0, 14) + '...' : rawLabel;
      svg.appendChild(catText);
    }

    container.appendChild(svg);
  }

  return {
    renderBarChart: renderBarChart
  };
});
