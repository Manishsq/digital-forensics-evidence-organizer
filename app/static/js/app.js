/**
 * Digital Forensics Evidence Organizer — Frontend JS
 */

// ── Sidebar toggle (mobile) ──────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', (e) => {
      if (!sidebar.contains(e.target) && !toggle.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });
  }

  // ── Hash copy buttons ────────────────────────────────────
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', function () {
      const val = this.getAttribute('data-value');
      if (!val) return;
      navigator.clipboard.writeText(val).then(() => {
        const orig = this.innerHTML;
        this.innerHTML = '<i class="bi bi-check-lg"></i>';
        this.classList.add('btn-success');
        setTimeout(() => {
          this.innerHTML = orig;
          this.classList.remove('btn-success');
        }, 1500);
      }).catch(() => {
        // Fallback for HTTP contexts
        const ta = document.createElement('textarea');
        ta.value = val;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    });
  });

  // ── Auto-dismiss alerts after 6 s ───────────────────────
  document.querySelectorAll('.alert.alert-success, .alert.alert-info').forEach(el => {
    setTimeout(() => {
      if (el.parentNode) {
        el.style.transition = 'opacity .4s';
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 400);
      }
    }, 6000);
  });

  // ── Confirm destructive actions ──────────────────────────
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', function (e) {
      if (!confirm(this.getAttribute('data-confirm'))) {
        e.preventDefault();
      }
    });
  });

  // ── Timestamp display — convert to local time if desired ─
  // All timestamps are stored/displayed as UTC; this adds local hint.
  document.querySelectorAll('[data-utc]').forEach(el => {
    try {
      const d = new Date(el.getAttribute('data-utc') + 'Z');
      el.title = 'Local: ' + d.toLocaleString();
    } catch (_) {}
  });
});
