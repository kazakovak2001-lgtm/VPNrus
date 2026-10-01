package net.pocvpn.client.chaos

data class ChaosOperation(val component: String, val gatewayId: String? = null, val transport: String? = null)

sealed class ChaosOutcome {
    object Success : ChaosOutcome()
    data class Failure(val failure: ChaosFailure) : ChaosOutcome()
}

enum class ExpectedTransition { RETRY, FALLBACK_TRANSPORT, NEXT_GATEWAY, FAIL_CLOSED, RECOVERED, NONE }

data class ChaosStep(
    val operation: ChaosOperation,
    val outcome: ChaosOutcome,
    val delayMillis: Long = 0,
    val repeat: Int = 1,
    val expectedTransition: ExpectedTransition = ExpectedTransition.NONE,
) {
    init {
        require(delayMillis >= 0) { "delay must be non-negative" }
        require(repeat in 1..100) { "repeat must be bounded to 1..100" }
        require(operation.component.isNotBlank()) { "component is required" }
    }
}

data class ChaosEvidence(
    val sequence: Int,
    val logicalTimeMillis: Long,
    val operation: ChaosOperation,
    val outcome: ChaosOutcome,
    val expectedTransition: ExpectedTransition,
)

/** Ordered, deterministic, logical-time fault source. It never invokes product policy. */
class ScriptedChaosEngine(steps: List<ChaosStep>, startMillis: Long = 0) {
    private val pending = ArrayDeque<ChaosStep>().apply {
        steps.forEach { step -> repeat(step.repeat) { addLast(step.copy(repeat = 1)) } }
    }
    private val recorded = mutableListOf<ChaosEvidence>()
    var logicalTimeMillis: Long = startMillis
        private set

    fun next(actual: ChaosOperation): ChaosOutcome {
        val step = checkNotNull(pending.removeFirstOrNull()) { "unexpected operation $actual: script exhausted" }
        check(step.operation == actual) { "operation order mismatch: expected ${step.operation}, got $actual" }
        logicalTimeMillis += step.delayMillis
        recorded += ChaosEvidence(recorded.size + 1, logicalTimeMillis, actual, step.outcome, step.expectedTransition)
        return step.outcome
    }

    fun evidence(): List<ChaosEvidence> = recorded.toList()
    fun assertExhausted() = check(pending.isEmpty()) { "${pending.size} scripted outcome(s) were not consumed" }
}
