package com.example.taskpal

/** Kotlin helper with no problems: the scan should find nothing here. */
object Reminders {
    fun nextReminder(times: List<Long>, now: Long): Long? = times.filter { it > now }.minOrNull()
}
