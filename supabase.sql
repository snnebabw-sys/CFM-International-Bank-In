-- CFM International Bank: SIMULATION ONLY.
-- Run in Supabase SQL Editor. Do not use for real-money services.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  email text not null unique,
  phone text not null default '',
  country text not null default '',
  role text not null default 'customer' check (role in ('admin','customer')),
  status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null default now()
);

create table if not exists public.accounts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique references public.profiles(id) on delete cascade,
  account_number text not null unique,
  full_name text not null,
  balance numeric(18,2) not null default 0 check (balance >= 0),
  currency text not null check (currency in ('GBP','NGN','USD','EUR','CAD')),
  status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null default now()
);

create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  reference text not null unique,
  kind text not null check (kind in ('opening','admin_credit','transfer_in','transfer_out')),
  account_id uuid not null references public.accounts(id),
  counterparty_account text not null default '',
  counterparty_name text not null default '',
  counterparty_country text not null default '',
  amount numeric(18,2) not null check (amount > 0),
  currency text not null check (currency in ('GBP','NGN','USD','EUR','CAD')),
  description text not null default '',
  status text not null default 'completed' check (status in ('completed')),
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);

create table if not exists public.admin_audit (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid not null references public.profiles(id),
  action text not null,
  account_number text not null,
  amount numeric(18,2),
  reason text not null,
  created_at timestamptz not null default now()
);

create index if not exists transactions_account_created_idx
  on public.transactions(account_id, created_at desc);
create index if not exists accounts_number_idx on public.accounts(account_number);

alter table public.profiles enable row level security;
alter table public.accounts enable row level security;
alter table public.transactions enable row level security;
alter table public.admin_audit enable row level security;

-- No direct client-side table access. Server uses service role after checking auth and role.
revoke all on public.profiles from anon, authenticated;
revoke all on public.accounts from anon, authenticated;
revoke all on public.transactions from anon, authenticated;
revoke all on public.admin_audit from anon, authenticated;

-- Account numbers are generated in the database and retried on collision.
create or replace function public.cfm_new_account_number()
returns text language plpgsql security definer set search_path = public, pg_temp as $$
declare n text;
begin
  loop
    n := 'CFM' || lpad(floor(random() * 1000000000)::bigint::text, 9, '0');
    exit when not exists(select 1 from public.accounts where account_number = n);
  end loop;
  return n;
end;
$$;

create or replace function public.cfm_create_customer_account(
  p_user_id uuid, p_full_name text, p_phone text, p_country text,
  p_currency text, p_initial_balance numeric, p_opening_note text, p_admin_id uuid
) returns jsonb language plpgsql security definer set search_path = public, auth, pg_temp as $$
declare v_email text; v_number text; v_account public.accounts%rowtype;
begin
  if not exists(select 1 from public.profiles where id=p_admin_id and role='admin' and status='active') then
    raise exception 'CFM:Admin permission required';
  end if;
  if p_initial_balance < 0 or round(p_initial_balance,2) <> p_initial_balance then
    raise exception 'CFM:Invalid initial balance';
  end if;
  select email into v_email from auth.users where id=p_user_id;
  if v_email is null then raise exception 'CFM:User does not exist'; end if;

  insert into public.profiles(id,full_name,email,phone,country,role,status)
  values(p_user_id,p_full_name,v_email,coalesce(p_phone,''),p_country,'customer','active');
  v_number := public.cfm_new_account_number();
  insert into public.accounts(owner_id,account_number,full_name,balance,currency)
  values(p_user_id,v_number,p_full_name,p_initial_balance,p_currency)
  returning * into v_account;

  if p_initial_balance > 0 then
    insert into public.transactions(reference,kind,account_id,amount,currency,description,created_by)
    values('CFM-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,16)),
      'opening',v_account.id,p_initial_balance,p_currency,coalesce(nullif(p_opening_note,''),'Opening demo balance'),p_admin_id);
  end if;
  insert into public.admin_audit(admin_id,action,account_number,amount,reason)
  values(p_admin_id,'create_account',v_number,p_initial_balance,coalesce(p_opening_note,'Account created'));
  return jsonb_build_object('account_number',v_number,'full_name',p_full_name,
    'balance',p_initial_balance,'currency',p_currency,'status','active');
end $$;

create or replace function public.cfm_admin_credit(
  p_admin_id uuid, p_account_number text, p_amount numeric, p_reason text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare a public.accounts%rowtype;
begin
  if not exists(select 1 from public.profiles where id=p_admin_id and role='admin' and status='active') then
    raise exception 'CFM:Admin permission required';
  end if;
  if p_amount <= 0 or round(p_amount,2) <> p_amount then raise exception 'CFM:Invalid amount'; end if;
  select * into a from public.accounts where account_number=p_account_number and status='active' for update;
  if not found then raise exception 'CFM:Active account not found'; end if;
  update public.accounts set balance=balance+p_amount where id=a.id;
  insert into public.transactions(reference,kind,account_id,amount,currency,description,created_by)
  values('CFM-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,16)),
    'admin_credit',a.id,p_amount,a.currency,p_reason,p_admin_id);
  insert into public.admin_audit(admin_id,action,account_number,amount,reason)
  values(p_admin_id,'credit',a.account_number,p_amount,p_reason);
  return jsonb_build_object('account_number',a.account_number,'amount',p_amount,'currency',a.currency);
end $$;

create or replace function public.cfm_transfer(
  p_sender_id uuid, p_receiver_account text, p_receiver_name text,
  p_receiver_country text, p_amount numeric, p_description text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare s public.accounts%rowtype; r public.accounts%rowtype; ref text;
begin
  if not exists(select 1 from public.profiles where id=p_sender_id and role='customer' and status='active') then
    raise exception 'CFM:Customer account is not active';
  end if;
  if p_amount <= 0 or round(p_amount,2) <> p_amount then raise exception 'CFM:Invalid amount'; end if;
  select * into s from public.accounts where owner_id=p_sender_id and status='active' for update;
  if not found then raise exception 'CFM:Sender account not found'; end if;
  select * into r from public.accounts where account_number=p_receiver_account and status='active' for update;
  if not found then raise exception 'CFM:Demo recipient account not found'; end if;
  if s.id=r.id then raise exception 'CFM:You cannot transfer to your own account'; end if;
  if s.currency <> r.currency then raise exception 'CFM:Recipient account must use the same currency in this demo'; end if;
  if lower(trim(r.full_name)) <> lower(trim(p_receiver_name)) then raise exception 'CFM:Receiver name does not match the demo account'; end if;
  if s.balance < p_amount then raise exception 'CFM:Insufficient demo balance'; end if;

  update public.accounts set balance=balance-p_amount where id=s.id;
  update public.accounts set balance=balance+p_amount where id=r.id;
  ref := 'CFM-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,16));
  insert into public.transactions(reference,kind,account_id,counterparty_account,counterparty_name,counterparty_country,amount,currency,description,created_by)
  values(ref,'transfer_out',s.id,r.account_number,r.full_name,p_receiver_country,p_amount,s.currency,coalesce(nullif(p_description,''),'Demo transfer'),p_sender_id);
  insert into public.transactions(reference,kind,account_id,counterparty_account,counterparty_name,counterparty_country,amount,currency,description,created_by)
  values(ref,'transfer_in',r.id,s.account_number,s.full_name,'',p_amount,r.currency,coalesce(nullif(p_description,''),'Demo transfer'),p_sender_id);
  return jsonb_build_object('reference',ref,'created_at',now(),'sender_name',s.full_name,
    'sender_account',s.account_number,'receiver_name',r.full_name,'receiver_account',r.account_number,
    'receiver_country',p_receiver_country,'amount',p_amount,'currency',s.currency,
    'description',coalesce(nullif(p_description,''),'Demo transfer'),'simulation',true);
end $$;

create or replace function public.cfm_list_my_transactions(p_user_id uuid)
returns table(reference text,kind text,direction text,amount numeric,currency text,description text,
  counterparty text,status text,created_at timestamptz)
language plpgsql security definer set search_path = public, pg_temp as $$
declare aid uuid;
begin
  select id into aid from public.accounts where owner_id=p_user_id;
  if aid is null then return; end if;
  return query
    select t.reference,t.kind,
      case when t.kind in ('opening','admin_credit','transfer_in') then 'in' else 'out' end,
      t.amount,t.currency,t.description,
      case when t.counterparty_name <> '' then t.counterparty_name else t.kind end,
      t.status,t.created_at
    from public.transactions t where t.account_id=aid order by t.created_at desc limit 5;
end $$;

-- Lock down function execution. Server calls these using the service-role connection.
revoke all on function public.cfm_new_account_number() from public, anon, authenticated;
revoke all on function public.cfm_create_customer_account(uuid,text,text,text,text,numeric,text,uuid) from public, anon, authenticated;
revoke all on function public.cfm_admin_credit(uuid,text,numeric,text) from public, anon, authenticated;
revoke all on function public.cfm_transfer(uuid,text,text,text,numeric,text) from public, anon, authenticated;
revoke all on function public.cfm_list_my_transactions(uuid) from public, anon, authenticated;
grant execute on function public.cfm_new_account_number() to service_role;
grant execute on function public.cfm_create_customer_account(uuid,text,text,text,text,numeric,text,uuid) to service_role;
grant execute on function public.cfm_admin_credit(uuid,text,numeric,text) to service_role;
grant execute on function public.cfm_transfer(uuid,text,text,text,numeric,text) to service_role;
grant execute on function public.cfm_list_my_transactions(uuid) to service_role;

-- IMPORTANT ADMIN SETUP:
-- Create your first admin user in Supabase Authentication > Users.
-- Then replace the UUID below with that user's UUID and run:
-- insert into public.profiles(id,full_name,email,role,status)
-- select id, 'CFM Demo Administrator', email, 'admin', 'active'
-- from auth.users where id = 'REPLACE-WITH-ADMIN-USER-UUID';
