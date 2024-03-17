import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EnergyRateComponent } from './energy-rate.component';

describe('EnergyRateComponent', () => {
  let component: EnergyRateComponent;
  let fixture: ComponentFixture<EnergyRateComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ EnergyRateComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EnergyRateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
