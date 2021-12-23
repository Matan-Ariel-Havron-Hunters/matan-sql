-- In the HUNTERS_DB.RAW schema, choose 5 tables and describe the main interesting columns.
SELECT SAMPLE_TIME,
       UUID,
       SEVERITY,                         --log security severity level
       EVENT_TYPE,                       --okta operation type
       DISPLAY_MESSAGE,                  --event explanation
       ACTOR_TYPE,
       ACTOR_DISPLAY_NAME,               --name of the actor
       ACTOR_ALTERNATE_ID,               --email of actor
       CLIENT_USER_AGENT_RAW_USER_AGENT, -- all actor details, json formatted
       OUTCOME_REASON,                   --reason for outcome result
       OUTCOME_RESULT                    --success/fail/etc.
  FROM HUNTERS_DB.RAW.OKTA_LOGS
 LIMIT 10;

SELECT EVENT_TIME,
       AID,             --agent id
       AIP,-- agent ip
       EVENT_SIMPLE_NAME,
       EVENT_PLATFORM,  --os
       NAME,            --event name, something human understandable
       IMAGE_FILE_NAME, --file attached (if exists)
       TARGET_FILE_NAME,
       COMMAND_LINE,    --command used
       DOMAIN_NAME      --domain accessed if exists
  FROM HUNTERS_DB.RAW.CROWDSTRIKE_RAW_EVENTS
 LIMIT 10;

SELECT AWS_REGION,        --self explanatory
       SOURCE_IP_ADDRESS, --the aws service server address?
       EVENT_NAME,        --type of action performed
       EVENT_SOURCE,      --aws service from which the event occured
       READ_ONLY,         --self explanatory
       USER_IDENTITY,     --user that activated the action
       EVENT_TIME
  FROM HUNTERS_DB.RAW.AWS_CLOUDTRAIL
 LIMIT 50;

SELECT SAMPLE_TIME,
       STATUS,     --active/staged/etc.
       CREATED,    --user creation ts
       LAST_LOGIN,
       PROFILE_FIRST_NAME,
       PROFILE_LAST_NAME,
       PROFILE_EMAIL,
       CREDENTIALS --credential type
  FROM HUNTERS_DB.RAW.OKTA_USERS
 LIMIT 10;

SELECT RESOURCE_NAME,
       ARN,
       AVAILABILITY_ZONE,
       AWS_REGION,
       RESOURCE_CREATION_TIME
  FROM HUNTERS_DB.RAW.AWS_CONFIG
 LIMIT 10;

-- What is the average daily event count in the past 14 days in the tables you chose?
SELECT TABLE_NAME,
       AVG(DATE_COUNT) AS DAY_AVG
  FROM (SELECT COUNT(*) AS DATE_COUNT,
               TABLE_NAME
          FROM (SELECT TO_DATE(SAMPLE_TIME) AS DATE,
                       'OKTA_LOGS'          AS TABLE_NAME
                  FROM HUNTERS_DB.RAW.OKTA_LOGS
                 UNION ALL
                SELECT TO_DATE(EVENT_TIME)      AS DATE,
                       'CROWDSTRIKE_RAW_EVENTS' AS TABLE_NAME
                  FROM HUNTERS_DB.RAW.CROWDSTRIKE_RAW_EVENTS
                 UNION ALL
                SELECT TO_DATE(EVENT_TIME) AS DATE,
                       'AWS_CLOUDTRAIL'    AS TABLE_NAME
                  FROM HUNTERS_DB.RAW.AWS_CLOUDTRAIL
                 UNION ALL
                SELECT TO_DATE(SAMPLE_TIME) AS DATE,
                       'OKTA_USERS'         AS TABLE_NAME
                  FROM HUNTERS_DB.RAW.OKTA_USERS
                 UNION ALL
                SELECT TO_DATE(RESOURCE_CREATION_TIME) AS DATE,
                       'AWS_CONFIG'                    AS TABLE_NAME
                  FROM HUNTERS_DB.RAW.AWS_CONFIG)
         WHERE DATE > DATEADD('day', -14, CURRENT_TIMESTAMP)
         GROUP BY DATE, TABLE_NAME)
 GROUP BY TABLE_NAME;

-- How many CrowdStrike agents does Hunters have?
SELECT COUNT(DISTINCT AID) AS C
  FROM HUNTERS_DB.RAW.CROWDSTRIKE_RAW_EVENTS
;

-- How may Okta users does Hunters have?
SELECT COUNT(DISTINCT ID) AS C
  FROM HUNTERS_DB.RAW.OKTA_USERS
;

-- Is there a user in Okta that doesn’t have a CrowdStrike agent?
-- ????
SELECT *
  FROM HUNTERS_DB.RAW.CROWDSTRIKE_RAW_EVENTS
 LIMIT 10;
SELECT *
  FROM HUNTERS_DB.RAW.OKTA_USERS
 LIMIT 10;

-- How many Hunters employees' users appear in the AWS CloudTrail logs?
SELECT COUNT(*) AS TOTAL
  FROM (SELECT DISTINCT PROFILE_EMAIL,
                        IFF(PROFILE_EMAIL IN (
                            SELECT DISTINCT COALESCE(SPLIT_PART(SPLIT_PART(USER_IDENTITY_ARN, '/', -1), ':', -1),
                                                     USER_IDENTITY_USER_NAME) AS PROFILE_EMAIL
                              FROM HUNTERS_DB.RAW.AWS_CLOUDTRAIL AS AWS
                             WHERE EVENT_TIME > DATEADD('day', -1, CURRENT_TIMESTAMP)
                               AND PROFILE_EMAIL LIKE '%@hunters.ai'), 'true', 'false'
                            ) AS IS_IN_AWS
          FROM HUNTERS_DB.RAW.OKTA_USERS AS OKTA)
 GROUP BY IS_IN_AWS
HAVING IS_IN_AWS = 'true';

-- How many non-employee users appear in the AWS CloudTrail logs?
SELECT COUNT(*)
  FROM (SELECT DISTINCT COALESCE(SPLIT_PART(SPLIT_PART(USER_IDENTITY_ARN, '/', -1), ':', -1),
                                 USER_IDENTITY_USER_NAME) AS USER_NAME_OR_ARN_ID
          FROM HUNTERS_DB.RAW.AWS_CLOUDTRAIL
         WHERE EVENT_TIME > DATEADD('day', -1, CURRENT_TIMESTAMP)
           AND (SPLIT_PART(SPLIT_PART(USER_IDENTITY_ARN, '/', -1), ':', -1) LIKE '%@%'
             OR USER_IDENTITY_USER_NAME LIKE '%@%')
           AND USER_NAME_OR_ARN_ID NOT IN (SELECT DISTINCT PROFILE_EMAIL FROM HUNTERS_DB.RAW.OKTA_USERS));

-- Who is the most active user, per application, in G Suite Activity logs during the last month?
SELECT DISTINCT ID_APPLICATION_NAME,
                ACTOR_EMAIL,
                COUNT(*) AS COUNT_EMAIL
  FROM HUNTERS_DB.RAW.GSUITE_ACTIVITY
 WHERE ID_TIME > TO_TIMESTAMP('2021-04-20')
 GROUP BY ID_APPLICATION_NAME, ACTOR_EMAIL
     QUALIFY ROW_NUMBER() OVER (PARTITION BY ID_APPLICATION_NAME ORDER BY COUNT_EMAIL DESC) = 1
 ORDER BY COUNT_EMAIL DESC;

-- What is the oldest entity Hunters have in our AWS account? (hint: use AWS Config)
SELECT RESOURCE_NAME,
       RESOURCE_CREATION_TIME
  FROM HUNTERS_DB.RAW.AWS_CONFIG
      QUALIFY ROW_NUMBER() OVER (ORDER BY RESOURCE_CREATION_TIME) = 1;
