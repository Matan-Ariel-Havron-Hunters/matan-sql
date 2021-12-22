SELECT PUBLISHED, SEVERITY, EVENT_TYPE, DISPLAY_MESSAGE, ACTOR_DISPLAY_NAME, ACTOR_TYPE, ACTOR_ALTERNATE_ID
FROM HUNTERS_DB.RAW.OKTA_LOGS
WHERE PUBLISHED > dateadd(day, -7, current_timestamp)
  and ACTOR_ALTERNATE_ID = 'matan.ariel@hunters.ai'
LIMIT 100;

SELECT EVENT_TYPE, count(*) cnt
FROM HUNTERS_DB.RAW.OKTA_LOGS
WHERE PUBLISHED > dateadd(day, -7, current_timestamp)
  and ACTOR_ALTERNATE_ID = 'matan.ariel@hunters.ai'
group by EVENT_TYPE
order by cnt desc
LIMIT 100;

select TARGET[0]:displayName::varchar target_display_name,
       count(distinct actor_alternate_id) actor_cnt
from HUNTERS_DB.RAW.OKTA_LOGS
where PUBLISHED > dateadd(day, -7, current_timestamp)
and EVENT_TYPE = 'user.authentication.sso'
group by target_display_name
order by actor_cnt desc
limit 100;

select OKTA_LOGS.ACTOR_ALTERNATE_ID,
       OKTA_USERS.PROFILE:mobilePhone::varchar mobile_phone,
       count(distinct TARGET_APP_INSTANCE_DISPLAY_NAME) app_cnt
from HUNTERS_DB.RAW.OKTA_LOGS inner join HUNTERS_DB.RAW.OKTA_USERS on OKTA_LOGS.ACTOR_ALTERNATE_ID = OKTA_USERS.PROFILE_EMAIL
where PUBLISHED > dateadd(day, -7, current_timestamp)
and OKTA_USERS.SAMPLE_TIME > dateadd(day, -7, current_timestamp)
and EVENT_TYPE = 'user.authentication.sso'
and TARGET_APP_INSTANCE_DISPLAY_NAME is not null
group by ACTOR_ALTERNATE_ID, mobile_phone
limit 200;

SELECT OKTA_LOGS.ACTOR_ALTERNATE_ID,
       OKTA_USERS.PROFILE:mobilePhone::VARCHAR mobile_phone,
       COUNT(DISTINCT TARGET_APP_INSTANCE_DISPLAY_NAME)
FROM HUNTERS_DB.RAW.OKTA_LOGS INNER JOIN HUNTERS_DB.RAW.OKTA_USERS ON
OKTA_LOGS.ACTOR_ALTERNATE_ID = OKTA_USERS.PROFILE_EMAIL
WHERE PUBLISHED > DATEADD(DAY, -7, CURRENT_TIMESTAMP)
  AND okta_users.SAMPLE_TIME > DATEADD(DAY, -7, CURRENT_TIMESTAMP)
  AND event_type = 'user.authentication.sso'
  AND TARGET_APP_INSTANCE_DISPLAY_NAME IS NOT NULL
GROUP BY ACTOR_ALTERNATE_ID, mobile_phone
LIMIT 100;