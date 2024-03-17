import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EnergyRateSettingsComponent } from './energy-rate-settings.component';

describe('EnergyRateSettingsComponent', () => {
  let component: EnergyRateSettingsComponent;
  let fixture: ComponentFixture<EnergyRateSettingsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ EnergyRateSettingsComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EnergyRateSettingsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
