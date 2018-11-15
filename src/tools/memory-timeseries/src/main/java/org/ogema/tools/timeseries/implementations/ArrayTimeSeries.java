/**
 * Copyright 2011-2018 Fraunhofer-Gesellschaft zur Förderung der angewandten Wissenschaften e.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ogema.tools.timeseries.implementations;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import org.ogema.core.channelmanager.measurements.FloatValue;

import org.ogema.core.channelmanager.measurements.Quality;
import org.ogema.core.channelmanager.measurements.SampledValue;
import org.ogema.core.channelmanager.measurements.Value;
import org.ogema.core.timeseries.InterpolationMode;
import org.ogema.core.timeseries.ReadOnlyTimeSeries;
import org.ogema.core.timeseries.TimeSeries;
import org.ogema.tools.timeseries.api.InterpolationFunction;
import org.ogema.tools.timeseries.api.MemoryTimeSeries;
import org.ogema.tools.timeseries.interpolation.LinearInterpolation;
import org.ogema.tools.timeseries.interpolation.NearestInterpolation;
import org.ogema.tools.timeseries.interpolation.NoInterpolation;
import org.ogema.tools.timeseries.interpolation.StepInterpolation;
import org.ogema.tools.memoryschedules.tools.SampledValueSortedList;

/**
 * TimeSeries implementation internally based on an array of sampled values. In
 * a logging-like scenario where data are always appended behind the existing
 * ones this should have a better performance than the {@link TreeTimeSeries}.
 *
 * @author Timo Fischer, Fraunhofer IWES
 */
public class ArrayTimeSeries implements MemoryTimeSeries {

	private final Class<? extends Value> m_type;
	private final SampledValueSortedList m_values = new SampledValueSortedList();
	private InterpolationFunction m_interpolationFunction = new NoInterpolation();
	private InterpolationMode m_interpolationMode = InterpolationMode.NONE;
	private long m_lastCalculationTime = 0;

	public ArrayTimeSeries(Class<? extends Value> type) {
		this.m_type = type;
	}

	/**
	 * Copy-constructor from another time series. Note that the TimeSeries
	 * interface provides no means of telling the user what the actual data type
	 * is, so it must be provided explicitly.
	 */
	public ArrayTimeSeries(ReadOnlyTimeSeries other, Class<? extends Value> type) {
		this.m_type = type;
		final List<SampledValue> values = other.getValues(Long.MIN_VALUE);
		addValues(values);
		setInterpolationMode(other.getInterpolationMode());
	}

	@Override
	public void write(TimeSeries schedule) {
		final List<SampledValue> values = m_values.getValues();
		schedule.replaceValues(0, Long.MAX_VALUE, values);
		schedule.setInterpolationMode(getInterpolationMode());
	}

	@Override
	public void write(TimeSeries schedule, long from, long to) {
		final List<SampledValue> values = m_values.getValues();
		schedule.replaceValues(from, to, values);
		schedule.setInterpolationMode(getInterpolationMode());
	}

	@Override
	public ArrayTimeSeries read(ReadOnlyTimeSeries schedule) {
		m_values.clear();
		final List<SampledValue> newValues = schedule.getValues(0);
		m_values.addValuesCopies(newValues);
		setInterpolationMode(schedule.getInterpolationMode());

		return this;
	}

	@Override
	public ArrayTimeSeries read(ReadOnlyTimeSeries schedule, long start, long end) {
		m_values.clear();
		final List<SampledValue> newValues = schedule.getValues(start, end);
		m_values.addValuesCopies(newValues);
		setInterpolationMode(schedule.getInterpolationMode());
		return this;
	}
	
	@Override
	public ArrayTimeSeries readWithBoundaries(ReadOnlyTimeSeries schedule, long start, long end) {
		m_values.clear();
		setInterpolationMode(schedule.getInterpolationMode());
		final List<SampledValue> newValues = schedule.getValues(start, end);
		List<SampledValue> resultList = new ArrayList<SampledValue>();
		if (end < start)
			return this;
		if (newValues.isEmpty() || start < newValues.get(0).getTimestamp()) {
			SampledValue sv = schedule.getValue(start);
			if (sv != null)
				resultList.add(new SampledValue(sv));
		}
		resultList.addAll(newValues);
		if (end > start) {
			SampledValue sv = schedule.getValue(end);
			if (sv != null)
				resultList.add(new SampledValue(sv));
		}
		m_values.addValuesCopies(resultList);
		return this;
	}

	@Override
	final public SampledValue getValue(long time) {
		if (!isInsideTimeSeriesRange(time)) {
			return null;
		}
		final int idx = m_values.getIndexBelow(time);
		final SampledValue left = (idx != SampledValueSortedList.NO_SUCH_INDEX) ? m_values.get(idx) : null;
		final SampledValue right = (idx < m_values.size() - 1) ? m_values.get(idx + 1) : null;
		return m_interpolationFunction.interpolate(left, right, time, m_type);
	}

	/**
	 * Checks if a given timestamp is in the range generally covered by the
	 * schedule (irrespective of the value qualities).
	 */
	private boolean isInsideTimeSeriesRange(long timestamp) {
		if (m_values.isEmpty()) {
			return false;
		}
		final long tmin = m_values.get(0).getTimestamp();
		final long tmax = m_values.get(m_values.size() - 1).getTimestamp();
		switch (m_interpolationMode) {
		case NEAREST:
			return true; // since there is at least one point there is alwayst a nearest one.
		case STEPS:
			return (timestamp >= tmin);
		case NONE:
		case LINEAR:
			return ((timestamp >= tmin) && (timestamp <= tmax));
		default:
			throw new UnsupportedOperationException("Unsupported interpolation mode encountered: "
					+ m_interpolationMode.toString());
		}
	}

	//	private boolean isInsideTimeSeriesRange(long timestamp) {
	//		return !m_values.isEmpty()
	//				&& ((m_values.get(0).getTimestamp() <= timestamp) && (m_values.get(m_values.size() - 1).getTimestamp() >= timestamp));
	//	}
	@Override
	public SampledValue getNextValue(long time) {
		return m_values.getNextValue(time);
	}

	@Override
        @Deprecated
	final public Long getTimeOfLatestEntry() {
		return null;
	}

	@Override
	final public Long getLastCalculationTime() {
		return m_lastCalculationTime;
	}

	@Override
	public void addValue(SampledValue value) {
		m_values.addValue(value);
	}

	@Override
	public boolean addValue(long timestamp, Value value) {
		addValue(new SampledValue(value, timestamp, Quality.GOOD));
		return true;
	}

	@Override
	public boolean addValue(long timestamp, Value value, long timeOfCalculation) {
		addValue(timestamp, value);
		m_lastCalculationTime = timeOfCalculation;
		return true;
	}

	// used in a constructor -> final
	@Override
	public final boolean addValues(Collection<SampledValue> values) {
		// TODO make more performant by sorting only once, not after every new value insterted.
		for (SampledValue value : values) {
			addValue(value);
		}
		return true;
	}

	@Override
	public boolean addValues(Collection<SampledValue> values, long timeOfCalculation) {
		addValues(values);
		m_lastCalculationTime = timeOfCalculation;
		return true;
	}

	@Override
	public boolean deleteValues() {
		m_values.clear();
		return true;
	}

	@Override
	final public boolean deleteValues(long endTime) {
		deleteValues(0, endTime);
		return true;
	}

	@Override
	public boolean deleteValues(long startTime, long endTime) {
		m_values.deleteValues(startTime, endTime);
		return true;
	}

	@Override
	public boolean replaceValues(long startTime, long endTime, Collection<SampledValue> values) {
		deleteValues(startTime, endTime);
		addValues(values);
		return true;
	}

	@Override
	final public boolean setInterpolationMode(InterpolationMode mode) {
		m_interpolationMode = mode;
		switch (mode) {
		case NONE:
			m_interpolationFunction = new NoInterpolation();
			break;
		case LINEAR:
			m_interpolationFunction = new LinearInterpolation();
			break;
		case NEAREST:
			m_interpolationFunction = new NearestInterpolation();
			break;
		case STEPS:
			m_interpolationFunction = new StepInterpolation();
			break;
		default:
			throw new UnsupportedOperationException("Interpolation mode " + mode + " not supported.");
		}
		return true;
	}

	@Override
	final public InterpolationMode getInterpolationMode() {
		return m_interpolationMode;
	}

	@Override
	public Class<? extends Value> getValueType() {
		return m_type;
	}

	@Override
	public List<SampledValue> getValues(long startTime) {
		return m_values.getValues(startTime);
	}

	@Override
	public List<SampledValue> getValues(long startTime, long endTime) {
		return m_values.getValues(startTime, endTime);
	}

	@Override
    public void shiftTimestamps(long dt) {
        final List<SampledValue> shiftedValues = new ArrayList<>(m_values.getValues().size());
        for (SampledValue value : m_values.getValues()) {
            final long t = value.getTimestamp() + dt;
            // if (t<0) continue;
            final SampledValue newValue = new SampledValue(value.getValue(), t, value.getQuality());
            shiftedValues.add(newValue);
        }
        m_values.clear();
        m_values.addValuesCopies(shiftedValues);
    }

	@Override
	public MemoryTimeSeries clone() {
		return new ArrayTimeSeries(this, m_type);
	}

	@Override
	public boolean replaceValuesFixedStep(long startTime, List<Value> values, long stepSize) {
		final long endTime = startTime + stepSize * values.size();
		deleteValues(startTime, endTime);
		long t = startTime;
		for (Value value : values) {
			addValue(t, value);
			t += stepSize;
		}
		return true;
	}

	@Override
	public boolean replaceValuesFixedStep(long startTime, List<Value> values, long stepSize, long timeOfCalculation) {
		replaceValuesFixedStep(startTime, values, stepSize);
		m_lastCalculationTime = timeOfCalculation;
		return true;
	}

	@Override
        @Deprecated
	public final boolean addValueSchedule(long startTime, long stepSize, List<Value> values) {
		return replaceValuesFixedStep(startTime, values, stepSize);
	}

	@Override
        @Deprecated
	public final boolean addValueSchedule(long startTime, long stepSize, List<Value> values, long timeOfCalculation) {
		return replaceValuesFixedStep(startTime, values, stepSize, timeOfCalculation);
	}

	@Override
	public SampledValue getValueSecure(long t) {
		final SampledValue result = getValue(t);
		return (result != null) ? result : new SampledValue(new FloatValue(0.f), t, Quality.BAD);
	}
	
	@Override
	public SampledValue getPreviousValue(long time) {
		return m_values.getPreviousValue(time);
	}

	@Override
	public boolean isEmpty() {
		return m_values.isEmpty();
	}

	@Override
	public boolean isEmpty(long startTime, long endTime) {
		return m_values.isEmpty(startTime, endTime);
	}

	@Override
	public int size() {
		return m_values.size();
	}

	@Override
	public int size(long startTime, long endTime) {
		return m_values.size(startTime, endTime);
	}

	@Override
	public Iterator<SampledValue> iterator() {
		return m_values.iterator();
	}

	@Override
	public Iterator<SampledValue> iterator(long startTime, long endTime) {
		return m_values.iterator(startTime, endTime);
	}
	
	

}
