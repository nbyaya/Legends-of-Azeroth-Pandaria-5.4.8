
-- waypoint_scripts add column Comment
ALTER TABLE `waypoint_scripts` 
ADD COLUMN `Comment` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' AFTER `guid`;

-- Jenn Langston (1328) 
UPDATE `creature` SET `position_x`=-8612.41, `position_y`=408.669, `position_z`=102.925, `orientation`=5.39708, `movement_type`=2 WHERE `guid`=188747;
DELETE FROM `waypoint_data` WHERE `id` IN(188747,1887470);
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`, `move_flag`, `action`, `action_chance`, `wpguid`) VALUES 
(1887470, 1, -8613.545, 391.4908, 110.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 2,-8603.045, 399.2408, 110.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 3, -8601.295, 402.4908, 110.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 4, -8607.795, 410.9908, 107.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 5, -8613.045, 417.7408, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 6,-8616.795, 419.2408, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 7,-8617.795, 415.4908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 8, -8611.045, 406.9908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 9,-8611.545, 402.4908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 10, -8615.545, 398.9908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 11,-8620.295, 401.4908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 12, -8625.795, 408.9908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 13, -8629.295, 408.9908, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 14, -8629.295, 405.2408, 103.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 15, -8623.795, 397.9908, 107.2298 , NULL, 0, 0, 0, 100, 0),
(1887470, 16, -8618.545, 391.7408, 110.2298 , NULL, 0, 0, 0, 100, 0);

-- Kaellin Tarvane (47320)
DELETE FROM `creature_addon` WHERE `guid`=189250;
INSERT INTO `creature_addon` (`guid`, `path_id`, `mount`, `bytes1`, `bytes2`, `emote`, `ai_anim_kit`, `movement_anim_kit`, `melee_anim_kit`, `auras`) 
VALUES (189250, 0, 0, 0, 0, 469, 0, 0, 0, '32783');

-- Dar Rummond (50161)
DELETE FROM `creature_addon` WHERE `guid`=235459; 
INSERT INTO `creature_addon` (`guid`, `path_id`, `mount`, `bytes1`, `bytes2`, `emote`, `ai_anim_kit`, `movement_anim_kit`, `melee_anim_kit`, `auras`) 
VALUES (235459, 0, 0, 0, 0, 469, 0, 0, 0, '32783');

-- Myra Tyrngaarde (5109)
DELETE FROM `creature_text` WHERE `CreatureID`=5109;
INSERT INTO `creature_text` (`CreatureID`, `GroupID`, `ID`, `Text`, `Type`, `Language`, `Probability`, `Emote`, `Duration`, `Sound`, `BroadcastTextId`, `TextRange`, `comment`) VALUES 
(5109, 0, 0, 'Fresh bread, baked this very morning.', 12, 7, 100, 0, 0, 0, 4014, 0, 'Myra Tyrngaarde'),
(5109, 0, 1, 'Fresh bread for sale!', 12, 7, 100, 0, 0, 0, 4013, 0, 'Myra Tyrngaarde'),
(5109, 0, 2, 'Come get yer fresh bread!', 12, 7, 100, 0, 0, 0, 4015, 0, 'Myra Tyrngaarde');
UPDATE `creature_template` SET `AIName`="SmartAI" WHERE `entry`=5109;
DELETE FROM `smart_scripts` WHERE `entryorguid`=5109;
INSERT INTO `smart_scripts` (`entryorguid`, `source_type`, `id`, `link`, `event_type`, `event_phase_mask`, `event_chance`, `event_flags`, `event_param1`, `event_param2`, `event_param3`, `event_param4`, `event_param5`, `action_type`, `action_param1`, `action_param2`, `action_param3`, `action_param4`, `action_param5`, `action_param6`, `target_type`, `target_param1`, `target_param2`, `target_param3`, `target_param4`, `target_x`, `target_y`, `target_z`, `target_o`, `comment`) VALUES 
(5109, 0, 0, 0, 1, 0, 100, 0, 10000, 15000, 40000, 60000, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 'Myra Tyrngaarde - Out of Combat - Say Line 0');
UPDATE `creature_addon` SET `path_id`=1806480 WHERE `guid`=180648; 
DELETE FROM `waypoint_data` WHERE `id` IN(180648,1806480);
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`, `move_flag`, `action`, `action_chance`, `wpguid`) VALUES 
(1806480, 1, -4956.59, -978.85, 501.63, NULL, 0, 0, 0, 100, 0),
(1806480, 2, -4966.61, -974.932, 502.78, NULL, 0, 0, 0, 100, 0),
(1806480, 3, -4977.69, -967.015, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 4, -4978.87, -957.095, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 5, -4966.55, -946.783, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 6, -4946.39, -929.878, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 7, -4924.84, -913.595, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 8, -4904.37, -898.434, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 9, -4898.43, -902.386, 501.659, NULL, 0, 0, 0, 100, 0),
(1806480, 10, -4891.91, -916.892, 501.628, NULL, 0, 0, 0, 100, 0),
(1806480, 11, -4902.03, -933.63, 501.531, NULL, 0, 0, 0, 100, 0),
(1806480, 12, -4925.54, -947.789, 501.581, NULL, 0, 0, 0, 100, 0),
(1806480, 13, -4940.07, -966.556, 501.586, NULL, 0, 0, 0, 100, 0);

-- Sognar Cliffbeard (5124)
UPDATE `creature_addon` SET `path_id`=93100 WHERE `guid`=9310; 
DELETE FROM `waypoint_data` WHERE `id` IN(9310,93100);
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`, `move_flag`, `action`, `action_chance`, `wpguid`) VALUES 
(93100, 1, -4947.64, -1205.36, 501.659, NULL, 0, 0, 0, 100, 0),
(93100, 2, -4957.72, -1193.18, 501.659, NULL, 0, 0, 0, 100, 0),
(93100, 3, -4974.97, -1183.97, 501.651, NULL, 0, 0, 0, 100, 0),
(93100, 4, -4983.42, -1169.04, 501.655, NULL, 0, 0, 0, 100, 0),
(93100, 5, -5002.73, -1160.77, 501.66, NULL, 0, 0, 0, 100, 0),
(93100, 6, -5014.96, -1164.36, 501.658, NULL, 0, 0, 0, 100, 0),
(93100, 7, -5017.35, -1177.44, 501.64, NULL, 0, 0, 0, 100, 0),
(93100, 8, -5006.69, -1195.86, 501.66, NULL, 0, 0, 0, 100, 0),
(93100, 9, -4991.03, -1215.02, 501.678, NULL, 0, 0, 0, 100, 0),
(93100, 10, -4976.49, -1233.44, 501.679, NULL, 0, 0, 0, 100, 0),
(93100, 11, -4963.13, -1249.54, 501.672, NULL, 0, 0, 0, 100, 0),
(93100, 12, -4950.89, -1261.21, 501.667, NULL, 0, 0, 0, 100, 0),
(93100, 13, -4932.9, -1258.33, 501.663, NULL, 0, 0, 0, 100, 0),
(93100, 14, -4925.25, -1245.36, 501.66, NULL, 0, 0, 0, 100, 0),
(93100, 15, -4926.88, -1234.47, 501.654, NULL, 0, 0, 0, 100, 0),
(93100, 16, -4941.88, -1220.39, 501.652, NULL, 0, 0, 0, 100, 0);

-- Thief Catcher Shadowdelve (14363)
DELETE FROM `creature` WHERE `guid` IN (9598); -- delete duplicate spawns
DELETE FROM `creature_addon` WHERE `guid` IN (9598); -- delete duplicate spawns
UPDATE `creature_addon` SET `path_id`=1806130, `bytes2`=1 WHERE `guid`=180613; 
DELETE FROM `waypoint_data` WHERE `id` IN(180613,1806130,9598);
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`, `move_flag`, `action`, `action_chance`, `wpguid`) VALUES 
(1806130, 1, -4886.97, -891.763, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 2, -4906.81, -884.844, 501.66, NULL, 0, 0, 0, 100, 0),
(1806130, 3, -4929.05, -856.469, 501.661, NULL, 0, 0, 0, 100, 0),
(1806130, 4, -4952.72, -869.076, 501.639, NULL, 0, 0, 0, 100, 0),
(1806130, 5, -4988.78, -898.986, 501.648, NULL, 0, 0, 0, 100, 0),
(1806130, 6, -5017.84, -932.51, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 7, -4985.22, -957.64, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 8, -4958.79, -941.614, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 9, -4947.84, -930.124, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 10, -4950.35, -921.719, 504.263, NULL, 0, 0, 0, 100, 0),
(1806130, 11, -4961.11, -913.848, 503.837, NULL, 0, 0, 0, 100, 0),
(1806130, 12, -4956.32, -904.182, 503.839, NULL, 0, 0, 0, 100, 0),
(1806130, 13, -4960.76, -914.107, 503.873, NULL, 0, 0, 0, 100, 0),
(1806130, 14, -4956.32, -904.182, 503.839, NULL, 0, 0, 0, 100, 0),
(1806130, 15, -4950.29, -908.22, 503.839, NULL, 0, 0, 0, 100, 0),
(1806130, 16, -4950.21, -918.283, 504.262, NULL, 0, 0, 0, 100, 0),
(1806130, 17, -4942.2, -927.994, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 18, -4935.65, -936.283, 503.042, NULL, 0, 0, 0, 100, 0),
(1806130, 19, -4931.63, -949.347, 501.609, NULL, 0, 0, 0, 100, 0),
(1806130, 20, -4915.17, -957.814, 501.509, NULL, 0, 0, 0, 100, 0),
(1806130, 21, -4906.88, -973.011, 501.447, NULL, 0, 0, 0, 100, 0),
(1806130, 22, -4898.35, -983.751, 503.94, NULL, 0, 0, 0, 100, 0),
(1806130, 23, -4891.35, -992.121, 503.94, NULL, 0, 0, 0, 100, 0),
(1806130, 24, -4885.1, -986.439, 503.94, NULL, 0, 0, 0, 100, 0),
(1806130, 25, -4888.36, -983.674, 503.94, NULL, 0, 0, 0, 100, 0),
(1806130, 26, -4895.44, -985.192, 503.94, NULL, 0, 0, 0, 100, 0),
(1806130, 27, -4904.65, -975.419, 501.437, NULL, 0, 0, 0, 100, 0),
(1806130, 28, -4908.02, -960.372, 501.498, NULL, 0, 0, 0, 100, 0),
(1806130, 29, -4880.32, -920.64, 501.561, NULL, 0, 0, 0, 100, 0),
(1806130, 30, -4833.69, -904.184, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 31, -4797.36, -906.421, 497.923, NULL, 0, 0, 0, 100, 0),
(1806130, 32, -4780.09, -905.943, 499.229, NULL, 0, 0, 0, 100, 0),
(1806130, 33, -4763.68, -907.05, 501.627, NULL, 0, 0, 0, 100, 0),
(1806130, 34, -4721.88, -922.563, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 35, -4691.69, -946.508, 501.668, NULL, 0, 0, 0, 100, 0),
(1806130, 36, -4679.95, -969.957, 501.67, NULL, 0, 0, 0, 100, 0),
(1806130, 37, -4650.12, -982.774, 501.66, NULL, 0, 0, 0, 100, 0),
(1806130, 38, -4635.55, -960.367, 501.661, NULL, 0, 0, 0, 100, 0),
(1806130, 39, -4651.67, -935.212, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 40, -4687.28, -922.145, 501.662, NULL, 0, 0, 0, 100, 0),
(1806130, 41, -4721.49, -905.883, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 42, -4757.44, -890.981, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 43, -4785.5, -884.328, 501.659, NULL, 0, 0, 0, 100, 0),
(1806130, 44, -4815.04, -883.25, 501.663, NULL, 0, 0, 0, 100, 0),
(1806130, 45, -4846.72, -886.106, 501.659, NULL, 0, 0, 0, 100, 0);

-- Thief Catcher Farmountain (14365)
DELETE FROM `creature` WHERE `guid` IN (31,180611); -- delete duplicate spawns
DELETE FROM `creature_addon` WHERE `guid` IN (31,180611); -- delete duplicate spawns
UPDATE `creature_addon` SET `path_id`=1693510, `bytes2`=1 WHERE `guid`=169351; 
DELETE FROM `waypoint_data` WHERE `id` IN(180611,169351,1693510);
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`, `move_flag`, `action`, `action_chance`, `wpguid`) VALUES 
(1693510, 1, -5007, -1116.34, 501.68, NULL, 0, 0, 0, 100, 0),
(1693510, 2, -5003.02, -1142.08, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 3, -4998.46, -1179.69, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 4, -4982.61, -1226.39, 501.679, NULL, 0, 0, 0, 100, 0),
(1693510, 5, -4944.21, -1255.97, 501.663, NULL, 0, 0, 0, 100, 0),
(1693510, 6, -4925.57, -1250.11, 501.661, NULL, 0, 0, 0, 100, 0),
(1693510, 7, -4923.1, -1236.33, 501.655, NULL, 0, 0, 0, 100, 0),
(1693510, 8, -4945.75, -1214.15, 501.662, NULL, 0, 0, 0, 100, 0),
(1693510, 9, -4969.67, -1187.34, 501.66, NULL, 0, 0, 0, 100, 0),
(1693510, 10, -4991.06, -1151.82, 501.654, NULL, 0, 0, 0, 100, 0),
(1693510, 11, -4997.53, -1115.96, 501.622, NULL, 0, 0, 0, 100, 0),
(1693510, 12, -4994.73, -1091.5, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 13, -4992.42, -1058.82, 497.939, NULL, 0, 0, 0, 100, 0),
(1693510, 14, -4989.01, -1039.41, 501.656, NULL, 0, 0, 0, 100, 0),
(1693510, 15, -4983.64, -1019.23, 501.653, NULL, 0, 0, 0, 100, 0),
(1693510, 16, -4962.49, -981.229, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 17, -4929.97, -957.357, 501.567, NULL, 0, 0, 0, 100, 0),
(1693510, 18, -4915.2, -960.314, 501.499, NULL, 0, 0, 0, 100, 0),
(1693510, 19, -4904.06, -976.867, 501.431, NULL, 0, 0, 0, 100, 0),
(1693510, 20, -4896.08, -987.446, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 21, -4896.05, -992.92, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 22, -4889.55, -993.43, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 23, -4884.64, -985.495, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 24, -4888.78, -984.35, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 25, -4894.86, -986.589, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 26, -4899.7, -980.864, 503.94, NULL, 0, 0, 0, 100, 0),
(1693510, 27, -4904.34, -974.595, 501.44, NULL, 0, 0, 0, 100, 0),
(1693510, 28, -4914.21, -959.891, 501.501, NULL, 0, 0, 0, 100, 0),
(1693510, 29, -4935.67, -935.819, 503.068, NULL, 0, 0, 0, 100, 0),
(1693510, 30, -4948.83, -920.216, 504.264, NULL, 0, 0, 0, 100, 0),
(1693510, 31, -4959.34, -908.134, 503.838, NULL, 0, 0, 0, 100, 0),
(1693510, 32, -4963.37, -912.565, 503.837, NULL, 0, 0, 0, 100, 0),
(1693510, 33, -4955.28, -916.448, 504.261, NULL, 0, 0, 0, 100, 0),
(1693510, 34, -4944.97, -929.275, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 35, -4973.28, -956.894, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 36, -4992.38, -979.822, 501.659, NULL, 0, 0, 0, 100, 0),
(1693510, 37, -4994.91, -996.21, 501.661, NULL, 0, 0, 0, 100, 0),
(1693510, 38, -5007.27, -1025.46, 501.656, NULL, 0, 0, 0, 100, 0),
(1693510, 39, -5014.62, -1054.75, 501.737, NULL, 0, 0, 0, 100, 0),
(1693510, 40, -5016.1, -1099.32, 501.676, NULL, 0, 0, 0, 100, 0),
(1693510, 41, -5011.86, -1112.88, 501.669, NULL, 0, 0, 0, 100, 0);

-- John Turner (6175)
UPDATE `creature_addon` SET `path_id`=1806170 WHERE `guid`=180617; 
DELETE FROM `waypoint_data` WHERE `id` IN(180617,1806170);
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`, `move_flag`, `action`, `action_chance`, `wpguid`) VALUES 
(1806170, 1, -4895.61, -898.098, 501.659, 2.28638, 4000, 0, 10800, 100, 0),
(1806170, 2, -4859.86, -887.922, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 3, -4842.48, -885.565, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 4, -4842.48, -885.565, 501.659, 1.88496, 0, 0, 10801, 100, 0),
(1806170, 5, -4875.52, -889.064, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 6, -4895.69, -897.822, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 7, -4895.69, -897.822, 501.659, 2.25148, 4000, 0, 10802, 100, 0),
(1806170, 8, -4927.13, -915.428, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 9, -4951.84, -934.979, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 10, -4981.38, -966.579, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 11, -4983.74, -969.77, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 12, -4983.74, -969.77, 501.659, 2.44346, 4000, 0, 10803, 100, 0),
(1806170, 13, -5002.57, -1008.67, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 14, -5007.88, -1022.32, 501.655, NULL, 0, 0, 0, 100, 0),
(1806170, 15, -5012.98, -1052.93, 501.71, NULL, 0, 0, 0, 100, 0),
(1806170, 16, -5012.98, -1052.93, 501.71, 2.96706, 4000, 0, 10800, 100, 0),
(1806170, 17, -5006.93, -1021.7, 501.655, NULL, 0, 0, 0, 100, 0),
(1806170, 18, -4992.73, -985.894, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 19, -4981.07, -962.529, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 20, -4944.82, -930.416, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 21, -4906.59, -901.662, 501.659, NULL, 0, 0, 0, 100, 0),
(1806170, 22, -4895.61, -898.098, 501.659, NULL, 0, 0, 0, 100, 0);

DELETE FROM `waypoint_scripts` WHERE `id` IN (10800,10801,10802,10803);
INSERT INTO `waypoint_scripts` (`id`, `delay`, `command`, `datalong`, `datalong2`, `dataint`, `x`, `y`, `z`, `o`, `guid`, `Comment`) VALUES 
(10800, 0, 0, 0, 0, 2403, 0, 0, 0, 0, 1115, ''),
(10801, 0, 0, 0, 0, 2401, 0, 0, 0, 0, 1116, ''),
(10802, 0, 0, 0, 0, 2404, 0, 0, 0, 0, 1117, ''),
(10803, 0, 0, 0, 0, 2402, 0, 0, 0, 0, 1118, '');

-- Bimble Longberry (7978)
DELETE FROM `creature_addon` WHERE `guid`=180664;
INSERT INTO `creature_addon` (`guid`, `path_id`, `mount`, `bytes1`, `bytes2`, `emote`, `ai_anim_kit`, `movement_anim_kit`, `melee_anim_kit`, `auras`) 
VALUES (180664, 1806640, 0, 0, 0, 0, 0, 0, 0, NULL);
DELETE FROM `waypoint_data` WHERE `id`= 1806640;
INSERT INTO `waypoint_data` (`id`, `point`, `position_x`, `position_y`, `position_z`, `orientation`, `delay`) VALUES
(1806640, 0, -4641.676, -1014.932, 501.6339, NULL, 0),
(1806640, 1, -4657.603, -997.7568, 501.6321, NULL, 0),
(1806640, 2, -4667.463, -983.3502, 501.6437, NULL, 0),
(1806640, 3, -4681.746, -969.3637, 501.6546, NULL, 0),
(1806640, 4, -4689.504, -949.4026, 501.6545, NULL, 0),
(1806640, 5, -4699.37, -937.9786, 501.6603, NULL, 0),
(1806640, 6, -4711.072, -923.4749, 501.6495, NULL, 0),
(1806640, 7, -4707.845, -907.012, 501.6469, NULL, 0),
(1806640, 8, -4688.098, -902.9882, 501.6514, NULL, 0),
(1806640, 9, -4671.588, -914.5618, 501.644, NULL, 0),
(1806640, 10, -4655.948, -931.1495, 501.6501, NULL, 0),
(1806640, 11, -4636.642, -954.9941, 501.6523, NULL, 0),
(1806640, 12, -4621.53, -981.5043, 501.6445, NULL, 0),
(1806640, 13, -4617.623, -1000.404, 501.6521, NULL, 0),
(1806640, 14, -4626.838, -1012.12, 501.6395, NULL, 0),
(1806640, 15, -4641.676, -1014.932, 501.6339, NULL, 0),
(1806640, 16, -4657.603, -997.7568, 501.6321, NULL, 0);

-- Greatfather Winter's Helper (15745)  This text occur on 12-25, cannot impl in SAI
DELETE FROM `creature_text` WHERE `CreatureID`=15745;
INSERT INTO `creature_text` (`CreatureID`, `GroupID`, `ID`, `Text`, `Type`, `Language`, `Probability`, `Emote`, `Duration`, `Sound`, `BroadcastTextId`, `TextRange`, `comment`) VALUES
(15745, 0,0, 'Presents for everyone! Father Winter\'s put gifts under the tree for all.', 14, 0, 100, 0, 0, 0, 11430, 0, 'Greatfather Winter\'s Helper');
DELETE FROM `smart_scripts` WHERE `entryorguid`=5109;
INSERT INTO `smart_scripts` (`entryorguid`, `source_type`, `id`, `link`, `event_type`, `event_phase_mask`, `event_chance`, `event_flags`, `event_param1`, `event_param2`, `event_param3`, `event_param4`, `event_param5`, `action_type`, `action_param1`, `action_param2`, `action_param3`, `action_param4`, `action_param5`, `action_param6`, `target_type`, `target_param1`, `target_param2`, `target_param3`, `target_param4`, `target_x`, `target_y`, `target_z`, `target_o`, `comment`) VALUES 
(15745, 0, 0, 0, 1, 0, 100, 0, 10000, 15000, 40000, 60000, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 'Greatfather Winter\'s Helper - Out of Combat - Say Line 0');
