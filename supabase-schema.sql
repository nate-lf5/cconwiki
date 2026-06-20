-- =====================================================================
--  써클커넥션 Wiki · Supabase 데이터베이스 설치 스크립트
--  Supabase 대시보드 → SQL Editor 에 전체 복사해 붙여넣고 [Run] 하세요.
--  (한 번만 실행하면 됩니다. 회사 대표 이메일은 아래 OWNER_EMAIL 부분을 확인하세요.)
-- =====================================================================

-- ---------- 1. 테이블 ----------

-- 사용자 프로필 (구글 로그인 계정과 1:1 연결)
create table if not exists public.profiles (
  id      uuid primary key references auth.users(id) on delete cascade,
  email   text unique not null,
  name    text,
  dept    text default '',
  role    text not null default 'user'    check (role in ('user','admin')),
  status  text not null default 'new' check (status in ('new','pending','active','removed')),
  joined  timestamptz not null default now()
);

-- 위키 문서
create table if not exists public.articles (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  body         text not null default '',
  cat          text not null,
  tags         text[] not null default '{}',
  author_email text not null,
  author_name  text,
  status       text not null default 'pending' check (status in ('pending','approved','rejected','hidden')),
  views        int  not null default 0,
  reject       text default '',
  history      jsonb not null default '[]',
  attach       jsonb not null default '[]',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- ---------- 2. 보안 활성화 (RLS) ----------
alter table public.profiles enable row level security;
alter table public.articles enable row level security;

-- ---------- 3. 권한 판별 함수 ----------
create or replace function public.is_active() returns boolean
  language sql security definer stable as $$
  select exists(select 1 from public.profiles p
    where p.id = auth.uid() and p.status = 'active');
$$;

create or replace function public.is_admin() returns boolean
  language sql security definer stable as $$
  select exists(select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin' and p.status = 'active');
$$;

-- ---------- 4. 접근 정책 ----------

-- profiles: 로그인한 사용자는 프로필 목록 조회 가능(작성자 이름 표시·관리자 목록용)
drop policy if exists "profiles_read" on public.profiles;
create policy "profiles_read" on public.profiles
  for select to authenticated using (true);

-- profiles: 관리자만 다른 사용자 정보 수정(승인·퇴장·권한)
drop policy if exists "profiles_admin_update" on public.profiles;
create policy "profiles_admin_update" on public.profiles
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- articles: 공개글은 모든 활성 사용자가 열람, 본인 글·관리자는 전체 열람
drop policy if exists "articles_read" on public.articles;
create policy "articles_read" on public.articles
  for select to authenticated using (
    public.is_active() and (
      status = 'approved'
      or author_email = (auth.jwt() ->> 'email')
      or public.is_admin()
    )
  );

-- articles: 활성 사용자가 본인 명의로 작성(일반 사용자는 '승인 대기' 상태만)
drop policy if exists "articles_insert" on public.articles;
create policy "articles_insert" on public.articles
  for insert to authenticated with check (
    public.is_active()
    and author_email = (auth.jwt() ->> 'email')
    and (public.is_admin() or status = 'pending')
  );

-- articles: 본인 글 수정 가능, 관리자는 전체 수정
drop policy if exists "articles_update" on public.articles;
create policy "articles_update" on public.articles
  for update to authenticated using (
    public.is_active() and (author_email = (auth.jwt() ->> 'email') or public.is_admin())
  ) with check (
    public.is_active() and (author_email = (auth.jwt() ->> 'email') or public.is_admin())
  );

-- articles: 삭제는 관리자만
drop policy if exists "articles_delete" on public.articles;
create policy "articles_delete" on public.articles
  for delete to authenticated using (public.is_admin());

-- ---------- 5. 조회수 증가(보안 우회 함수) ----------
create or replace function public.increment_views(aid uuid) returns void
  language sql security definer as $$
  update public.articles set views = views + 1 where id = aid and status = 'approved';
$$;

-- ---------- 6. 구글 로그인 시 프로필 자동 생성 ----------
-- ccon.co.kr 도메인 계정만 등록되며, 대표 계정은 자동으로 관리자/활성 처리됩니다.
-- ★ 회사 도메인이나 대표 이메일이 다르면 아래 두 값을 바꾸세요.
create or replace function public.handle_new_user() returns trigger
  language plpgsql security definer as $$
declare
  v_domain text := split_part(new.email, '@', 2);
  v_owner  text := 'nate@ccon.co.kr';   -- ★ 대표(최초 관리자) 이메일
  v_allow  text := 'ccon.co.kr';        -- ★ 허용 도메인
begin
  if v_domain = v_allow then
    insert into public.profiles (id, email, name, role, status)
    values (
      new.id,
      new.email,
      coalesce(new.raw_user_meta_data ->> 'full_name',
               new.raw_user_meta_data ->> 'name',
               split_part(new.email, '@', 1)),
      case when new.email = v_owner then 'admin'  else 'user'   end,
      case when new.email = v_owner then 'active' else 'new'    end
    )
    on conflict (id) do nothing;
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- 6-1. 가입 신청 (첫 로그인 후 '신청' 버튼) ----------
-- 'new'(로그인만 한 상태) → 'pending'(승인 대기)로 본인 프로필을 전환합니다.
create or replace function public.apply_membership() returns void
  language plpgsql security definer as $$
begin
  update public.profiles set status = 'pending'
  where id = auth.uid() and status = 'new';
end;
$$;

-- ---------- 6-2. 검토 요청 (검색해도 없는 내용 요청) ----------
create table if not exists public.review_requests (
  id         uuid primary key default gen_random_uuid(),
  keyword    text not null,
  note       text default '',
  by_email   text not null,
  by_name    text,
  status     text not null default 'open' check (status in ('open','done')),
  created_at timestamptz not null default now()
);
alter table public.review_requests enable row level security;

-- 활성 사용자는 요청 목록 조회 가능
drop policy if exists "req_read" on public.review_requests;
create policy "req_read" on public.review_requests
  for select to authenticated using (public.is_active());

-- 활성 사용자는 본인 명의로 요청 등록
drop policy if exists "req_insert" on public.review_requests;
create policy "req_insert" on public.review_requests
  for insert to authenticated with check (
    public.is_active() and by_email = (auth.jwt() ->> 'email')
  );

-- 처리(완료/되돌리기)와 삭제는 관리자만
drop policy if exists "req_update" on public.review_requests;
create policy "req_update" on public.review_requests
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "req_delete" on public.review_requests;
create policy "req_delete" on public.review_requests
  for delete to authenticated using (public.is_admin());

-- ---------- 6-3. 카테고리 (관리자가 추가/삭제) ----------
create table if not exists public.categories (
  id          text primary key,
  name        text not null,
  emoji       text default '📁',
  description text default '',
  created_at  timestamptz not null default now()
);
alter table public.categories enable row level security;

drop policy if exists "cat_read" on public.categories;
create policy "cat_read" on public.categories
  for select to authenticated using (public.is_active());

drop policy if exists "cat_insert" on public.categories;
create policy "cat_insert" on public.categories
  for insert to authenticated with check (public.is_admin());

drop policy if exists "cat_update" on public.categories;
create policy "cat_update" on public.categories
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "cat_delete" on public.categories;
create policy "cat_delete" on public.categories
  for delete to authenticated using (public.is_admin());

-- ---------- 7. 시작용 샘플 문서 ----------
insert into public.articles (title, body, cat, tags, author_email, author_name, status, views) values
('연차 휴가 신청 방법 및 규정',
 '<h2>연차 휴가 개요</h2><p>입사 1년 미만은 매월 개근 시 <strong>1일</strong>의 연차가 발생하며, 1년 이상 근속자는 연 <strong>15일</strong>이 부여됩니다.</p><h2>신청 절차</h2><ol><li>그룹웨어 → 휴가 신청 메뉴 접속</li><li>희망 일자 및 사유 입력</li><li>팀장 승인 → 경영지원팀 확정</li></ol>',
 'leave', '{휴가,연차,신청}', 'nate@ccon.co.kr', 'Nathan (대표)', 'approved', 142),
('행사 기획 표준 프로세스 (RFP → 정산)',
 '<h2>1. 수주 및 RFP 분석</h2><p>클라이언트 RFP 접수 후 <strong>킥오프 미팅</strong>으로 목표·예산·일정을 확정합니다.</p><h2>2. 기획안 작성</h2><ul><li>컨셉 및 연출 시나리오</li><li>운영 인력 및 협력사 구성</li><li>예산안(견적서) 작성</li></ul><h2>3. 실행 및 운영</h2><p>D-7 통합 리허설, D-day 현장 운영.</p><h2>4. 정산</h2><p>행사 종료 후 <strong>2주 이내</strong> 정산서 제출.</p>',
 'event', '{기획,프로세스,RFP,정산}', 'nate@ccon.co.kr', 'Nathan (대표)', 'approved', 230),
('이벤트 예산 책정 가이드',
 '<h2>예산 항목</h2><ul><li><strong>연출/제작비</strong>: 무대·음향·조명·영상</li><li><strong>인건비</strong>: 운영 인력·MC·스태프</li><li><strong>대관/장비</strong>: 장소 임대·렌탈</li><li><strong>예비비</strong>: 총 예산의 5~10%</li></ul><h2>마진</h2><p>표준 대행 마진은 직접비의 <strong>15~20%</strong>.</p>',
 'event', '{예산,견적,정산}', 'nate@ccon.co.kr', 'Nathan (대표)', 'approved', 188),
('현장 운영 필수 체크리스트',
 '<h2>D-1</h2><ul><li>무대/음향/조명 셋업·사운드 체크</li><li>동선·사이니지 확인</li><li>비상 연락망 공유</li></ul><h2>D-day</h2><ul><li>리허설(개장 2시간 전)</li><li>스태프 브리핑</li><li>안전요원 배치 확인</li></ul>',
 'event', '{체크리스트,운영,현장}', 'nate@ccon.co.kr', 'Nathan (대표)', 'approved', 97),
('신규 입사자 온보딩 가이드',
 '<h2>첫 주 체크리스트</h2><ul><li>그룹웨어/메신저 계정 발급</li><li>보안 서약·사내 규정 숙지</li><li>담당 멘토 배정</li></ul><h2>필수 교육</h2><p>안전관리·개인정보보호·현장 운영 기초 교육을 1주 내 이수.</p>',
 'policy', '{온보딩,신입,인사}', 'nate@ccon.co.kr', 'Nathan (대표)', 'approved', 120),
('카페테리아 이용 및 식대 지원 안내',
 '<h2>운영 시간</h2><p>점심 11:30~13:00 / 저녁(행사 시) 18:00~19:00</p><h2>식대 지원</h2><p>1일 <strong>1만원</strong> 한도, 야근/행사 시 별도 정산.</p>',
 'welfare', '{식사,복지,식대}', 'nate@ccon.co.kr', 'Nathan (대표)', 'approved', 64);

-- =====================================================================
--  설치 완료! 이제 index.html 의 CONFIG 에 Supabase URL/Key 를 넣으면 됩니다.
-- =====================================================================
