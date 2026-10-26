from pathlib import Path
import re, shutil, datetime
ROOT=Path.cwd()
HERE=Path(__file__).resolve().parent
LINK='https://class101.net/ko/products/6ab24916418d9e6a56205e2c?viewMode=svod'
def banner(kind):
 return '<a class="class101-'+kind+'" href="'+LINK+'" target="_blank" rel="noopener noreferrer" aria-label="CLASS101 초급 일본어 실전 회화 강의 보기"><img src="/static/class101_'+kind+'.png" alt="CLASS101 초급 일본어 실전 회화 — 강의 보러 가기"></a>'
def transform_home(s):
 if 'class101-horizontal' in s: return s
 # Move the existing first content ad as a whole, preserving its slot and scripts.
 pat=r'<script\b[^>]*src="[^"]*pagead2[^\"]*"[^>]*>\s*</script>\s*<!--\s*content-ad-2\s*-->\s*<ins\b[^>]*class="adsbygoogle"[\s\S]*?</ins>\s*<script>[\s\S]*?</script>'
 m=re.search(pat,s)
 if not m: raise ValueError('홈의 content-ad-2 광고를 찾지 못했습니다. 원본 파일을 확인해주세요.')
 ad=m.group(0)
 s=s[:m.start()]+banner('horizontal')+s[m.end():]
 today=re.search(r'<section\b[^>]*class="today-wrap"[^>]*>[\s\S]*?</section>',s)
 if not today: raise ValueError('오늘의 회화 section을 찾지 못했습니다.')
 return s[:today.end()]+'\n<div class="class101-moved-ad">\n'+ad+'\n</div>\n'+s[today.end():]
def transform_side(s):
 if 'class101-vertical' in s: return s
 return re.sub(r'(<aside\b[^>]*class="side-link-nav"[^>]*>[\s\S]*?)(</aside>)',lambda m:m[1]+'\n'+banner('vertical')+'\n'+m[2],s)
CSS='''
/* CLASS101 banners */
.class101-horizontal{display:block;max-width:1000px;margin:24px auto 32px;line-height:0;border-radius:16px;overflow:hidden;}
.class101-horizontal img{display:block;width:100%;height:auto;}
.class101-vertical{display:block;width:100%;max-width:176px;margin:16px auto 0;line-height:0;border-radius:12px;overflow:hidden;}
.class101-vertical img{display:block;width:100%;height:auto;}
.class101-horizontal:focus-visible,.class101-vertical:focus-visible{outline:3px solid #1d70af;outline-offset:4px;}
.class101-moved-ad{max-width:1000px;margin:32px auto;clear:both;}
/* Keep the existing fixed navigation and its banner within the viewport. */
@media(min-width:1461px){.side-link-nav{left:auto!important;right:max(16px,calc((100vw - 1528px)/2))!important;max-height:calc(100vh - 196px);overflow-y:auto;scrollbar-width:thin;}}
@media(max-width:1460px){.side-link-nav{display:block!important;position:static!important;width:100%!important;margin:0 auto 24px!important;max-height:none!important;}.side-link-nav .class101-vertical{max-width:144px;}.side-link-nav .side-link-list{display:flex;flex-wrap:wrap;}.side-link-nav .side-link-item{flex:1 1 140px;}}
'''
def main():
 index=ROOT/'templates/index.html'; css=ROOT/'static/style.css'
 if not index.exists() or not css.exists(): raise SystemExit('이 파일을 templates와 static 폴더가 있는 travel-talk 프로젝트 폴더에 놓고 실행해주세요.')
 changes={index:transform_home(index.read_text(encoding='utf-8-sig'))}
 for p in (ROOT/'templates').rglob('*.html'):
  if p==index: continue
  before=p.read_text(encoding='utf-8-sig'); after=transform_side(before)
  if after!=before: changes[p]=after
 old=css.read_text(encoding='utf-8-sig')
 if '/* CLASS101 banners */' not in old: changes[css]=old+CSS
 # Validate assets before making any project changes.
 for kind in ['horizontal','vertical']:
  if not (HERE/'assets'/('class101_'+kind+'.png')).is_file(): raise SystemExit('assets 폴더를 apply_banners.py와 함께 복사해주세요.')
 backup=ROOT/('banner_backup_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
 for p,content in changes.items():
  dst=backup/p.relative_to(ROOT);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dst)
  p.write_text(content,encoding='utf-8')
 for kind in ['horizontal','vertical']:
  dst=ROOT/'static'/('class101_'+kind+'.png')
  if dst.exists():
   b=backup/dst.relative_to(ROOT);b.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(dst,b)
  shutil.copy2(HERE/'assets'/dst.name,dst)
 print('적용 완료:',len(changes),'개 코드 파일. 백업:',backup)
 print('로컬 서버를 실행한 뒤 홈과 상황별 회화·단어 모음 페이지를 확인하세요.')
if __name__=='__main__': main()
