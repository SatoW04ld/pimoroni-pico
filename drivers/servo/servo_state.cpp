#include "servo_state.hpp"

namespace servo {
  ServoState::ServoState() {
  }

  ServoState::ServoState(CalibrationType default_type)
    : calib(default_type) {
  }

  ServoState::ServoState(const Calibration& calibration) 
    : calib(calibration) {
  }

  float ServoState::enable() {
    // Has the servo not had a pulse value set before being enabled?
    if(last_enabled_pulse < MIN_VALID_PULSE) {
      // Set the servo to its middle
      return to_mid();
    }
    return _enable();
  }

  float ServoState::disable() {
    enabled = false;
    return 0.0f; // A zero pulse
  }

  float ServoState::_enable() {
    enabled = true;
    return last_enabled_pulse;
  }

  bool ServoState::is_enabled() const {
    return enabled;
  }

  float ServoState::get_pulse() const {
    return last_enabled_pulse;
  }

  float ServoState::set_pulse(float pulse) {
    if(pulse >= MIN_VALID_PULSE) {
      float value_out, pulse_out;
      if(calib.pulse_to_value(pulse, value_out, pulse_out)) {
        servo_value = value_out;
        last_enabled_pulse = pulse_out;
        return _enable();
      }
    }
    return disable();
  }

  float ServoState::get_value() const {
    return servo_value;
  }

  float ServoState::set_value(float value) {
    float pulse_out, value_out;
    if(calib.value_to_pulse(value, pulse_out, value_out)) {
      last_enabled_pulse = pulse_out;
      servo_value = value_out;
      return _enable();
    }
    return disable();
  }

  float ServoState::get_min_value() const {
    float value = 0.0f;
    if(calib.size() > 0) {
      value = calib.first().value;
    }
    return value;
  }

  float ServoState::get_mid_value() const {
    float value = 0.0f;
    if(calib.size() > 0) {
      const Calibration::Pair &first = calib.first();
      const Calibration::Pair &last = calib.last();
      value = (first.value + last.value) / 2.0f;
    }
    return value;
  }

  float ServoState::get_max_value() const {
    float value = 0.0f;
    if(calib.size() > 0) {
      value = calib.last().value;
    }
    return value;
  }

  float ServoState::to_min() {
    return set_value(get_min_value());
  }

  float ServoState::to_mid() {
    return set_value(get_mid_value());
  }

  float ServoState::to_max() {
    return set_value(get_max_value());
  }

  float ServoState::to_percent(float in, float in_min, float in_max) {
    float value = Calibration::map_float(in, in_min, in_max, get_min_value(), get_max_value());
    return set_value(value);
  }

  float ServoState::to_percent(float in, float in_min, float in_max, float value_min, float value_max) {
    float value = Calibration::map_float(in, in_min, in_max, value_min, value_max);
    return set_value(value);
  }

  Calibration& ServoState::calibration() {
    return calib;
  }

  const Calibration& ServoState::calibration() const {
    return calib;
  }

  uint32_t ServoState::pulse_to_level(float pulse, uint32_t resolution, float freq) {
    uint32_t level = 0;
    if(pulse >= MIN_VALID_PULSE) {
        level = (uint32_t)((pulse * (float)resolution * freq) / 1000000);
    }
    return level;
  }

};