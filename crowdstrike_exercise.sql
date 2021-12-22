select AGENT_ID,
       min(START_TIME) as first_seen,
       max(END_TIME) as last_seen
from HUNTERS_DB.INVESTIGATION.EDR_AIDS_EXTERNAL_IPS_OLD
where EXTERNAL_IP = '87.71.217.98'
group by AGENT_ID
limit 100;

select AGENT_ID, EXTERNAL_IP
from HUNTERS_DB.INVESTIGATION.EDR_AIDS_EXTERNAL_IPS_OLD
limit 100;

SELECT IMAGE_FILE_NAME,
       COMMAND_LINE,
       COUNT(*) occurrences,
       MIN(EVENT_TIME) first_seen,
       MAX(EVENT_TIME) last_seen
FROM HUNTERS_DB.RAW.CROWDSTRIKE_RAW_EVENTS
WHERE aid = '1abe2a95be1045a2819bd2f0452516f8'
  AND EVENT_TIME > current_timestamp - INTERVAL '7 day'
  AND EVENT_SIMPLE_NAME IN ('ProcessRollup2', 'SyntheticProcessRollup2')
  AND COMMAND_LINE IS NOT NULL
GROUP BY 1,2
ORDER BY occurrences DESC;