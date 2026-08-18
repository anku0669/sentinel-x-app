const targetInput = document.querySelector('#targets');
const profile = document.querySelector('#profile');
const maxHosts = document.querySelector('#maxHosts');
const scope = document.querySelector('#scope');
const terminal = document.querySelector('#terminal');

function classify(value){
  value=value.trim();
  if(!value) return null;
  if(value.includes('://')) return ['URL',value];
  if(value.includes('/')) return ['CIDR',value];
  if(value.includes(':')) return ['IPv6 / host',value];
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return ['IPv4',value];
  return ['Hostname / FQDN',value];
}

function normalize(){
  const raw=targetInput.value.split(',').map(x=>x.trim()).filter(Boolean);
  scope.classList.remove('hidden');
  if(!raw.length){scope.textContent='Enter a target scope first.';return;}
  const items=raw.map(classify).filter(Boolean);
  scope.innerHTML=items.map(x=>`<strong>${x[0]}</strong> · <code>${escapeHtml(x[1])}</code>`).join('<br>');
}

function command(){
  const target=targetInput.value.trim() || 'TARGET';
  let cmd=`./pentaforge '${target.replaceAll("'","'\\''")}' --authorized`;
  if(profile.value==='full') cmd+=' --profile full';
  const n=Number(maxHosts.value||64);
  if(n!==64) cmd+=` --max-hosts ${Math.min(4096,Math.max(1,n))}`;
  terminal.textContent=cmd;
}

function escapeHtml(s){return s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

document.querySelector('#normalize').addEventListener('click',normalize);
document.querySelector('#command').addEventListener('click',command);
document.querySelector('#copy').addEventListener('click',async()=>{
  await navigator.clipboard.writeText(terminal.textContent);
  document.querySelector('#copy').textContent='Copied';
  setTimeout(()=>document.querySelector('#copy').textContent='Copy',1200);
});
targetInput.addEventListener('input',()=>{if(targetInput.value.includes(',')) normalize();});
