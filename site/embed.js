(() => {
  const origin = 'https://printmaster.work';
  if (window.parent === window || new URLSearchParams(location.search).get('embed') !== '1') return;
  let embedded = false;
  const send = data => window.parent.postMessage(data, origin);
  const resize = () => send({
    type: 'printmaster:scans:resize',
    height: Math.ceil(document.body.getBoundingClientRect().height)
  });
  const navigate = hash => {
    if (typeof hash !== 'string' || !/^#[a-z][a-z0-9-]*$/.test(hash)) return;
    const target = document.getElementById(hash.slice(1));
    if (target) send({
      type: 'printmaster:scans:anchor', hash,
      top: target.getBoundingClientRect().top + window.scrollY
    });
  };
  window.addEventListener('message', event => {
    if (event.origin !== origin || event.source !== window.parent ||
        !event.data || event.data.type !== 'printmaster:scans:init') return;
    if (!embedded) {
      embedded = true;
      document.documentElement.setAttribute('data-embedded', '');
      document.querySelectorAll('a[href^="https://"]').forEach(link => {
        link.target = '_top';
      });
      new ResizeObserver(resize).observe(document.body);
      document.addEventListener('click', event => {
        const link = event.target.closest('a[href^="#"]');
        if (!link || event.defaultPrevented || event.button !== 0 ||
            event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        navigate(link.getAttribute('href'));
      });
    }
    resize();
    navigate(event.data.hash);
  });
  send({ type: 'printmaster:scans:ready' });
})();
