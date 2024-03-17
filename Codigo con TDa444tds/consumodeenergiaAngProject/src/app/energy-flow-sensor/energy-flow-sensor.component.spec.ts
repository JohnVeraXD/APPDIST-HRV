import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EnergyFlowSensorComponent } from './energy-flow-sensor.component';

describe('EnergyFlowSensorComponent', () => {
  let component: EnergyFlowSensorComponent;
  let fixture: ComponentFixture<EnergyFlowSensorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ EnergyFlowSensorComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EnergyFlowSensorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
