// Simulate a real drag: pointerdown, a stream of moves, pointerup — and count
// how many times the chart is actually redrawn while the button is held.
const fs = require('fs');
let renders = 0;
const winListeners = {};
const made = {};
function mk(tag,id){ const n={ tagName:tag,id,className:'',style:{},dataset:{},
  children:[],_text:'',_html:'',hidden:true,value:'',attrs:{},
  set textContent(v){this._text=String(v);}, get textContent(){return this._text;},
  set innerHTML(v){ this._html=String(v); if(this.id) renders++; },
  get innerHTML(){return this._html;},
  appendChild(c){this.children.push(c);return c;},removeChild(){},
  setAttribute(k,v){this.attrs[k]=v;},getAttribute(k){return this.attrs[k];},
  removeAttribute(){},focus(){},
  addEventListener(e,f){(this._on=this._on||{})[e]=f;},
  removeEventListener(){},
  getBoundingClientRect(){return{left:0,top:0,width:700,height:230,bottom:230};},
  offsetWidth:700,offsetHeight:230,
  classList:{_s:new Set(),toggle(c,o){o?this._s.add(c):this._s.delete(c);},
    add(c){this._s.add(c);},remove(c){this._s.delete(c);},contains(c){return this._s.has(c);}},
  querySelector(sel){ const q=(n._q=n._q||{}); return q[sel] || (q[sel]=mk(sel.replace(/\W/g,''))); },
  querySelectorAll(){return [];},onclick:null };
  return n; }
global.document={getElementById:id=>made[id]||(made[id]=mk('div',id)),
  createElement:t=>mk(t),createTextNode:()=>mk('#text'),
  querySelectorAll:()=>[],addEventListener:()=>{},hidden:false,body:{appendChild:c=>c}};
global.window={ addEventListener(e,f){ (winListeners[e]=winListeners[e]||[]).push(f); },
  removeEventListener(e,f){ if(winListeners[e]) winListeners[e]=winListeners[e].filter(x=>x!==f); },
  innerWidth:1400 };
global.location={hash:''}; global.history={replaceState:()=>{}};
global.setInterval=()=>1; global.clearInterval=()=>{}; global.clearTimeout=()=>{};
global.setTimeout=()=>1;
let frames=[]; global.requestAnimationFrame=f=>{frames.push(f);return frames.length;};
global.cancelAnimationFrame=i=>{frames[i-1]=null;};
global.fetch=()=>Promise.resolve({json:()=>Promise.resolve({})});
eval(fs.readFileSync('/tmp/dash.js','utf8') +
  '\nglobal.drawChart=drawChart; global.CHART_STATE=CHART_STATE; global.STATE=STATE;' +
  '\nglobal.applyView=applyView; global.renderChart=renderChart;');

const now = Math.floor(Date.now()/1000);
const rows = Array.from({length:200},(_,i)=>({ts:now-(200-i)*300,status:'OL',charge:90+(i%8),load:14}));
const host = made['probe'] = mk('div','probe');
drawChart(host, {rows, min:0, max:100, digits:0,
                 series:[{key:'charge',label:'Charge',color:'#3fb950'}]});
renders = 0;                              // ignore the initial paint

// zoom in first, otherwise the view is already at full extent and panning is
// clamped - which is correct behaviour, but tests nothing
const st = CHART_STATE['probe'];
const span = st.to - st.from;
applyView('probe', st.from + span * 0.35, st.to - span * 0.35);
renderChart('probe');
renders = 0;

const svg = host.querySelector('svg');
const before = { from: CHART_STATE['probe'].from, to: CHART_STATE['probe'].to };
console.log('  window listeners before the drag: %d',
            Object.values(winListeners).reduce((a,b)=>a+b.length,0));

svg._on.pointerdown({ button:0, clientX:400, preventDefault(){} });
console.log('  after pointerdown  : dragging class=%s, window listeners=%d',
            host.classList.contains('dragging'),
            Object.values(winListeners).reduce((a,b)=>a+b.length,0));

// drag left in ten steps, running any queued animation frame between them
[380,360,340,320,300,280,260,240,220,200].forEach(x => {
  winListeners['pointermove'].forEach(f => f({clientX:x, preventDefault(){}}));
  frames.splice(0).forEach(f => f && f());
});
const during = { from: CHART_STATE['probe'].from, to: CHART_STATE['probe'].to };
console.log('  during the drag    : %d redraw(s), window moved %d minutes',
            renders, Math.round((during.from - before.from)/60));

winListeners['pointerup'].forEach(f => f({}));
console.log('  after pointerup    : dragging class=%s, listeners left=%d, total redraws=%d',
            host.classList.contains('dragging'),
            Object.values(winListeners).reduce((a,b)=>a+b.length,0), renders);

console.log('\n  right button must not start a drag:');
renders = 0;
svg._on.pointerdown({ button:2, clientX:400, preventDefault(){} });
console.log('    dragging class=%s, redraws=%s',
            host.classList.contains('dragging'), renders);

console.log('\n  the other gestures still work:');
renders = 0;
const st2 = CHART_STATE['probe'];
const spanBefore = st2.to - st2.from;
svg._on.wheel({ clientX: 350, deltaY: -100, preventDefault(){} });
console.log('    wheel zoom in     : span %d%% of before, redraws=%d',
            Math.round((CHART_STATE['probe'].to - CHART_STATE['probe'].from) / spanBefore * 100), renders);
renders = 0;
svg._on.dblclick();
const full = CHART_STATE['probe'];
console.log('    double click reset: back to full extent=%s, redraws=%d',
            Math.abs(full.from - full.rows[0].ts) < 2, renders);
renders = 0;
svg._on.touchstart({ touches: [{clientX:100,clientY:0},{clientX:300,clientY:0}] });
svg._on.touchmove({ touches: [{clientX:50,clientY:0},{clientX:350,clientY:0}],
                    preventDefault(){} });
console.log('    pinch zoom        : redraws=%d', renders);
