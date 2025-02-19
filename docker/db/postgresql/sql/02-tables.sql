\c golyn;
SET search_path TO golyn;

DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS countries CASCADE;

-- TABLE REFRESH TOKEN
CREATE TABLE refresh_tokens
(
    id         SERIAL PRIMARY KEY,
    token      VARCHAR(255)             NOT NULL,
    username   VARCHAR(50)              NOT NULL,
    issued_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status     BOOLEAN                  NOT NULL DEFAULT FALSE
);

-- USERS
create table users
(
    id             uuid DEFAULT uuid_generate_v4(),
    first_name     varchar            not null,
    last_name      varchar            not null,
    alias          varchar            not null,
    age            integer,
    email          varchar            not null,
    password       varchar            not null,
    city           varchar,
    country        varchar,
    player_status  bool default true  not null,
    galleta_status bool default false not null,
    developer      bool default false not null,
    last_update    timestamp,
    created        timestamp          not null,
    constraint players_pk
        primary key (id)
);
comment on table users is 'User accounts';

-- COUNTRIES
CREATE TABLE countries
(
    country_code varchar(2),
    country_name varchar(100) not null,
    constraint countries_pk
        primary key (country_code)
);
comment on table countries is 'ISO3166 Apha-2';

-- PERMISSIONS
alter table refresh_tokens
    owner to dev;
alter table users
    owner to dev;
alter table countries
    owner to dev;